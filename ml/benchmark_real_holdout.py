#!/usr/bin/env python3
"""Leakage-safe benchmark over the checked-in CSIC dataset only.

The production training helper currently regenerates synthetic payloads. This
script intentionally bypasses that helper so no synthetic rows enter the
promotion evidence for roadmap task 2.4.
"""

import hashlib
import json
import os
import re
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, train_test_split

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.download_dataset import CSIC_PATH, download_csic_dataset
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request


RANDOM_STATE = 20260913
HOLDOUT_SIZE = 0.20
N_SPLITS = 5
MIN_BENIGN_RECALL = 0.985
MIN_ATTACK_RECALL = 0.85
REPORT_DIR = os.path.join(
    os.path.dirname(__file__), "models", "archive", "task2-4-real-holdout-cv-20260913"
)
REPORT_PATH = os.path.join(REPORT_DIR, "report.json")
SUSPICIOUS_URI_PATTERN = re.compile(
    r"(\.\.|~|\.bak|\.inc|\.old|\.sql|%|<|>|'|\"|;|\x60|\$)", re.IGNORECASE
)


def load_real_csic_dataset():
    download_csic_dataset()
    df = pd.read_csv(CSIC_PATH)
    required_columns = ["URI", "GET-Query", "POST-Data", "Method", "Class"]
    missing = [column for column in required_columns if column not in df.columns]
    if missing:
        raise ValueError(f"CSIC dataset is missing columns: {missing}")

    benign = df[df["Class"].astype(str).str.strip().str.lower() == "valid"]
    anomalous = df[df["Class"].astype(str).str.strip().str.lower() == "anomalous"]
    has_payload = anomalous["GET-Query"].notna() | anomalous["POST-Data"].notna()
    has_suspicious_uri = anomalous["URI"].astype(str).str.contains(
        SUSPICIOUS_URI_PATTERN, na=False
    )
    cleaned = pd.concat(
        [benign, anomalous[has_payload | has_suspicious_uri]], ignore_index=True
    )
    return cleaned


def prepare_features(df):
    request_columns = ["URI", "GET-Query", "POST-Data", "Method"]
    canonical_rows = (
        df[request_columns].fillna("").astype(str).agg("\x1f".join, axis=1)
    )
    request_hashes = canonical_rows.map(
        lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    )
    duplicate_mask = request_hashes.duplicated(keep=False)
    if duplicate_mask.any():
        labels = df["Class"].astype(str).str.strip().str.lower()
        labels = labels.map(lambda value: 1 if value == "anomalous" else 0)
        conflicts = (
            pd.DataFrame({"hash": request_hashes, "label": labels})
            .groupby("hash")["label"]
            .nunique()
        )
        if (conflicts > 1).any():
            raise ValueError("Conflicting labels found for an identical request")
        keep = ~request_hashes.duplicated(keep="first")
        df = df.loc[keep].reset_index(drop=True)
        request_hashes = request_hashes.loc[keep].reset_index(drop=True)

    if request_hashes.nunique() != len(request_hashes):
        raise AssertionError("SHA-256 hashes are not unique before splitting")

    features = []
    labels = []
    for _, row in df.iterrows():
        uri = "" if pd.isna(row["URI"]) else str(row["URI"])
        query = "" if pd.isna(row["GET-Query"]) else str(row["GET-Query"])
        body = "" if pd.isna(row["POST-Data"]) else str(row["POST-Data"])
        method = "GET" if pd.isna(row["Method"]) else str(row["Method"])
        full_url = f"{uri}?{query}" if query else uri
        features.append(
            extract_features_from_request(url=full_url, method=method, body=body)
        )
        labels.append(
            1 if str(row["Class"]).strip().lower() == "anomalous" else 0
        )

    return (
        pd.DataFrame(features)[EXTENDED_FEATURE_COLUMNS],
        pd.Series(labels),
        request_hashes.tolist(),
        {
            "source": "CSIC_2010_checked_in_cleaned_only",
            "rows_before_cleaning": int(len(pd.read_csv(CSIC_PATH))),
            "rows_after_label_cleanup": int(len(df)),
            "rows_after_sha256_deduplication": int(len(features)),
            "synthetic_rows_included": 0,
            "hash_algorithm": "sha256",
        },
    )


def build_model():
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=6,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


def confusion(y_true, probabilities, threshold):
    predictions = probabilities >= threshold
    return {
        "tn": int(((y_true == 0) & (~predictions)).sum()),
        "fp": int(((y_true == 0) & predictions).sum()),
        "fn": int(((y_true == 1) & (~predictions)).sum()),
        "tp": int(((y_true == 1) & predictions).sum()),
    }


def recall_from_confusion(matrix):
    benign_total = matrix["tn"] + matrix["fp"]
    attack_total = matrix["fn"] + matrix["tp"]
    return (
        matrix["tn"] / benign_total if benign_total else 0.0,
        matrix["tp"] / attack_total if attack_total else 0.0,
    )


def choose_threshold(y_true, probabilities):
    best = None
    for threshold in np.linspace(0.0, 1.0, 2001):
        matrix = confusion(y_true, probabilities, threshold)
        benign_recall, attack_recall = recall_from_confusion(matrix)
        if benign_recall < MIN_BENIGN_RECALL:
            continue
        candidate = (attack_recall, benign_recall, -matrix["fp"], threshold, matrix)
        if best is None or candidate[:3] > best[:3]:
            best = candidate
    if best is None:
        fallback = []
        for threshold in np.linspace(0.0, 1.0, 2001):
            matrix = confusion(y_true, probabilities, threshold)
            benign_recall, attack_recall = recall_from_confusion(matrix)
            fallback.append((benign_recall, attack_recall, threshold, matrix))
        benign_recall, attack_recall, threshold, matrix = max(fallback)
        status = "no_threshold_met_benign_gate"
    else:
        attack_recall, benign_recall, _, threshold, matrix = best
        status = (
            "passed_both_gates"
            if attack_recall >= MIN_ATTACK_RECALL
            else "failed_attack_gate"
        )
    return {
        "threshold": round(float(threshold), 6),
        "benign_recall": round(float(benign_recall), 6),
        "attack_recall": round(float(attack_recall), 6),
        "confusion_matrix": matrix,
        "calibration_status": status,
    }


def full_metrics(y_true, probabilities, threshold):
    matrix = confusion(y_true, probabilities, threshold)
    benign_recall, attack_recall = recall_from_confusion(matrix)
    total = len(y_true)
    correct = matrix["tn"] + matrix["tp"]
    return {
        "threshold": round(float(threshold), 6),
        "accuracy": round(correct / total, 6),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 6),
        "benign_recall": round(benign_recall, 6),
        "attack_recall": round(attack_recall, 6),
        "false_positive_rate": round(1.0 - benign_recall, 6),
        "confusion_matrix": matrix,
        "benign_count": int((y_true == 0).sum()),
        "attack_count": int((y_true == 1).sum()),
    }


def fit_predict(X_train, y_train, X_eval):
    model = build_model()
    model.fit(X_train, y_train)
    return model.predict_proba(X_eval)[:, 1]


def main():
    raw = load_real_csic_dataset()
    X, y, request_hashes, integrity = prepare_features(raw)
    X = X.reset_index(drop=True)
    y = y.reset_index(drop=True)
    indices = np.arange(len(X))

    dev_indices, holdout_indices = train_test_split(
        indices, test_size=HOLDOUT_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    dev_hashes = {request_hashes[index] for index in dev_indices}
    holdout_hashes = {request_hashes[index] for index in holdout_indices}
    if dev_hashes & holdout_hashes:
        raise AssertionError("SHA-256 leakage detected between dev and holdout")

    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    folds = []
    for fold_number, (train_rel, test_rel) in enumerate(
        cv.split(X.iloc[dev_indices], y.iloc[dev_indices]), start=1
    ):
        fold_train = dev_indices[train_rel]
        fold_test = dev_indices[test_rel]
        fit_indices, calibration_indices = train_test_split(
            fold_train,
            test_size=0.20,
            random_state=RANDOM_STATE + fold_number,
            stratify=y.iloc[fold_train],
        )
        fit_hashes = {request_hashes[index] for index in fit_indices}
        calibration_hashes = {request_hashes[index] for index in calibration_indices}
        test_hashes = {request_hashes[index] for index in fold_test}
        if (fit_hashes & calibration_hashes) or (fit_hashes & test_hashes) or (
            calibration_hashes & test_hashes
        ):
            raise AssertionError(f"SHA-256 leakage detected in fold {fold_number}")

        calibration_probabilities = fit_predict(
            X.iloc[fit_indices], y.iloc[fit_indices], X.iloc[calibration_indices]
        )
        calibration = choose_threshold(
            y.iloc[calibration_indices].to_numpy(), calibration_probabilities
        )
        test_probabilities = fit_predict(
            X.iloc[fit_indices], y.iloc[fit_indices], X.iloc[fold_test]
        )
        test_metrics = full_metrics(
            y.iloc[fold_test].to_numpy(),
            test_probabilities,
            calibration["threshold"],
        )
        folds.append(
            {
                "fold": fold_number,
                "fit_size": len(fit_indices),
                "calibration_size": len(calibration_indices),
                "test_size": len(fold_test),
                "calibration": calibration,
                "test": test_metrics,
            }
        )
        print(
            f"[fold {fold_number}/5] threshold={calibration['threshold']:.6f} "
            f"benign_recall={test_metrics['benign_recall']:.4f} "
            f"attack_recall={test_metrics['attack_recall']:.4f}"
        )

    fit_indices, calibration_indices = train_test_split(
        dev_indices,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y.iloc[dev_indices],
    )
    calibration_probabilities = fit_predict(
        X.iloc[fit_indices], y.iloc[fit_indices], X.iloc[calibration_indices]
    )
    final_calibration = choose_threshold(
        y.iloc[calibration_indices].to_numpy(), calibration_probabilities
    )
    holdout_probabilities = fit_predict(
        X.iloc[fit_indices], y.iloc[fit_indices], X.iloc[holdout_indices]
    )
    holdout = full_metrics(
        y.iloc[holdout_indices].to_numpy(),
        holdout_probabilities,
        final_calibration["threshold"],
    )
    report = {
        "experiment": "task-2.4-real-holdout-and-5-fold-stratified-cv",
        "random_state": RANDOM_STATE,
        "model": {
            "type": "RandomForestClassifier",
            "n_estimators": 200,
            "max_depth": 20,
            "min_samples_split": 6,
            "min_samples_leaf": 3,
            "class_weight": "balanced",
        },
        "safety_gate": {
            "benign_recall_required": MIN_BENIGN_RECALL,
            "attack_recall_required": MIN_ATTACK_RECALL,
        },
        "data_integrity": {
            **integrity,
            "development_rows": len(dev_indices),
            "unseen_holdout_rows": len(holdout_indices),
            "development_holdout_hash_overlap": len(dev_hashes & holdout_hashes),
            "cv_folds": N_SPLITS,
        },
        "feature_columns": list(X.columns),
        "cross_validation": folds,
        "final_calibration_on_development_data": final_calibration,
        "unseen_holdout": {
            "metrics": holdout,
            "promotion_gate_passed": (
                holdout["benign_recall"] >= MIN_BENIGN_RECALL
                and holdout["attack_recall"] >= MIN_ATTACK_RECALL
            ),
        },
        "production_artifacts_written": False,
    }
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2)
    print(f"[+] Wrote benchmark report: {REPORT_PATH}")
    print(
        f"[holdout] threshold={holdout['threshold']:.6f} "
        f"benign_recall={holdout['benign_recall']:.4f} "
        f"attack_recall={holdout['attack_recall']:.4f} "
        f"gate={'PASS' if report['unseen_holdout']['promotion_gate_passed'] else 'FAIL'}"
    )


if __name__ == "__main__":
    main()

