#!/usr/bin/env python3
"""
Roadmap Task 3.1-F & Task 2.3 Integrated Benchmark:
Real-World Data Augmented Benchmark (CSIC Cleaned + Real VPS Telemetry).
ZERO SYNTHETIC DATA, ZERO Naive Row Duplication.
Features: 31 Universal Structural Features from EXTENDED_FEATURE_COLUMNS.
Model: LightGBM vs. HistGradientBoosting vs. Random Forest.
Evaluation: 5-Fold Stratified Cross-Validation + Unseen Holdout with 100% SHA-256 Deduplication.
"""

import os
import sys
import glob
import json
import hashlib
import time
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import roc_auc_score, confusion_matrix
import lightgbm as lgb
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.benchmark_real_holdout import load_real_csic_dataset, choose_threshold, MIN_BENIGN_RECALL, MIN_ATTACK_RECALL, HOLDOUT_SIZE, N_SPLITS, RANDOM_STATE
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request

ARCHIVE_DIR = os.path.join(os.path.dirname(__file__), "models", "archive")


def load_real_telemetry():
    """Load and conservatively label real captured telemetry (Roadmap 3.1-D)."""
    telemetry_dir = os.path.join(os.path.dirname(__file__), "telemetry")
    files = sorted(glob.glob(os.path.join(telemetry_dir, "*.jsonl")))
    print(f"[*] Processing {len(files)} telemetry files...")

    rows = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                path = d.get("path", "")
                query = d.get("query_redacted", "")
                method = d.get("method", "GET")
                feats = d.get("features", {})

                # Roadmap 3.1-D: Conservative Labeling
                has_attack_sig = (
                    feats.get("keyword_matches", 0) > 0 or
                    feats.get("has_sql_operator", 0) > 0 or
                    feats.get("path_traversal_depth", 0) > 0 or
                    feats.get("suspicious_path_marker_count", 0) > 0 or
                    feats.get("has_ssrf_token", 0) > 0 or
                    feats.get("has_ssti_nosql", 0) > 0 or
                    feats.get("encoded_attack_token_count", 0) > 0 or
                    "batch/v1" in query or
                    "eval(" in query or
                    "../" in path
                )

                is_clean_benign = (
                    feats.get("is_clean_structure", 0) == 1 and
                    feats.get("special_char_count", 0) <= 2 and
                    not has_attack_sig and
                    (path in ["/", "/index.html", "/login.php", "/portal.php", "/setup.php", "/robots.txt"] or
                     path.startswith("/assets") or path.startswith("/images"))
                )

                if has_attack_sig:
                    cls_label = "Anomalous"
                elif is_clean_benign:
                    cls_label = "Valid"
                else:
                    continue  # Unlabeled/ambiguous excluded per 3.1-D

                rows.append({
                    "URI": path,
                    "GET-Query": query,
                    "POST-Data": "",
                    "Method": method,
                    "Class": cls_label,
                    "Source": "VPS_Telemetry_Real"
                })

    # Explicit columns so a run without telemetry files (public data only) still has a "Class" column
    df_telem = pd.DataFrame(rows, columns=["URI", "GET-Query", "POST-Data", "Method", "Class", "Source"])
    print(f"[+] Real Telemetry Loaded: {len(df_telem)} rows (Benign: {sum(df_telem['Class'] == 'Valid')}, Attack: {sum(df_telem['Class'] == 'Anomalous')})")
    return df_telem


def prepare_real_augmented_dataset():
    # 1. Base Real CSIC Dataset (No synthetic)
    df_csic = load_real_csic_dataset()
    df_csic["Source"] = "CSIC_2010_Cleaned"

    # 2. Real Telemetry Dataset (No synthetic)
    df_telem = load_real_telemetry()

    # Combine real datasets
    combined = pd.concat([df_csic, df_telem], ignore_index=True)
    rows_before = len(combined)

    # SHA-256 Deduplication
    request_cols = ["URI", "GET-Query", "POST-Data", "Method"]
    canonical = combined[request_cols].fillna("").astype(str).agg("\x1f".join, axis=1)
    hashes = canonical.map(lambda v: hashlib.sha256(v.encode("utf-8")).hexdigest())

    labels = combined["Class"].astype(str).str.strip().str.lower().map(lambda v: 1 if v == "anomalous" else 0)

    # Check for conflicts
    conflict_df = pd.DataFrame({"hash": hashes, "label": labels}).groupby("hash")["label"].nunique()
    if (conflict_df > 1).any():
        raise ValueError(f"Conflicting labels detected on {sum(conflict_df > 1)} identical hashes!")

    keep = ~hashes.duplicated(keep="first")
    df_dedup = combined.loc[keep].reset_index(drop=True)
    hashes_dedup = hashes.loc[keep].reset_index(drop=True)
    labels_dedup = labels.loc[keep].reset_index(drop=True)

    print(f"[+] Total Real-World Deduplicated Samples: {len(df_dedup)} (Cleaned from {rows_before})")
    print(f"    - Benign (Class 0): {sum(labels_dedup == 0)}")
    print(f"    - Attack (Class 1): {sum(labels_dedup == 1)}")

    # Extract 31 features
    features_list = []
    print("[*] Extracting 31 features from real requests...")
    for _, row in df_dedup.iterrows():
        uri = str(row["URI"]) if pd.notna(row.get("URI")) else ""
        query = str(row["GET-Query"]) if pd.notna(row.get("GET-Query")) else ""
        body = str(row["POST-Data"]) if pd.notna(row.get("POST-Data")) else ""
        method = str(row["Method"]) if pd.notna(row.get("Method")) else "GET"
        full_url = f"{uri}?{query}" if query else uri

        features_list.append(extract_features_from_request(url=full_url, method=method, body=body))

    X = pd.DataFrame(features_list)[EXTENDED_FEATURE_COLUMNS]
    y = labels_dedup

    return X, y, hashes_dedup.tolist(), {
        "dataset_name": "CSIC_2010_Cleaned + VPS_Real_Telemetry_Augmented",
        "synthetic_rows_included": 0,
        "rows_total": len(X),
        "benign_total": int(sum(y == 0)),
        "attack_total": int(sum(y == 1)),
        "feature_count": len(EXTENDED_FEATURE_COLUMNS),
        "hash_algorithm": "sha256"
    }


def evaluate_model_pipeline(model_factory, model_name, X_dev, y_dev, X_holdout, y_holdout):
    print(f"\n{'='*25} Benchmark: {model_name} {'='*25}")
    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    cv_thresholds = []
    cv_attack_recalls = []
    cv_benign_recalls = []

    for fold, (fit_idx, val_idx) in enumerate(skf.split(X_dev, y_dev), 1):
        m = model_factory()
        m.fit(X_dev.iloc[fit_idx], y_dev.iloc[fit_idx])
        val_probs = m.predict_proba(X_dev.iloc[val_idx])[:, 1]
        calib = choose_threshold(y_dev.iloc[val_idx], val_probs)
        cv_thresholds.append(calib["threshold"])
        cv_attack_recalls.append(calib["attack_recall"])
        cv_benign_recalls.append(calib["benign_recall"])

    mean_threshold = float(np.mean(cv_thresholds))
    print(f"[*] 5-Fold Stratified CV Mean Threshold: {mean_threshold:.4f}")
    print(f"    - Avg Benign Recall: {np.mean(cv_benign_recalls)*100:.2f}% (Safety Gate >= 98.5%)")
    print(f"    - Avg Attack Recall: {np.mean(cv_attack_recalls)*100:.2f}% (Goal >= 85%)")

    # Fit final model on Development set, evaluate on unseen holdout
    final_model = model_factory()
    t0 = time.time()
    final_model.fit(X_dev, y_dev)
    fit_time = time.time() - t0

    t1 = time.time()
    holdout_probs = final_model.predict_proba(X_holdout)[:, 1]
    infer_time_us = (time.time() - t1) / len(X_holdout) * 1000 * 1000

    holdout_preds = (holdout_probs >= mean_threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_holdout, holdout_preds).ravel()
    b_rec = tn / (tn + fp)
    a_rec = tp / (tp + fn)
    auc = float(roc_auc_score(y_holdout, holdout_probs))

    passed = bool(b_rec >= MIN_BENIGN_RECALL and a_rec >= MIN_ATTACK_RECALL)
    verdict = "PASSED ALL GATES" if passed else "BELOW GATE"

    print(f"[*] UNSEEN HOLDOUT EVALUATION ({len(X_holdout)} samples, 0 Leakage):")
    print(f"    - ROC-AUC:            {auc:.4f}")
    print(f"    - Latency per sample: {infer_time_us:.2f} µs")
    print(f"    - Benign Recall:      {b_rec*100:.2f}% (Safety Gate >= 98.5%)")
    print(f"    - Attack Recall:      {a_rec*100:.2f}% (Goal >= 85%)")
    print(f"    - Confusion Matrix:   TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"    - Gate Verdict:       {verdict}")

    return {
        "model": model_name,
        "fit_time_seconds": round(fit_time, 2),
        "infer_latency_us": round(infer_time_us, 2),
        "cv_5fold": {
            "mean_calibrated_threshold": round(mean_threshold, 4),
            "avg_benign_recall": round(float(np.mean(cv_benign_recalls)), 4),
            "avg_attack_recall": round(float(np.mean(cv_attack_recalls)), 4)
        },
        "unseen_holdout": {
            "roc_auc": round(auc, 4),
            "benign_recall": round(b_rec, 4),
            "attack_recall": round(a_rec, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "passed_safety_gate": passed
        }
    }


def main():
    X, y, hashes, integrity = prepare_real_augmented_dataset()

    # Stratified Train/Holdout Split (80% / 20%) with zero SHA-256 leakage
    row_indices = np.arange(len(X))
    dev_idx, holdout_idx = train_test_split(row_indices, test_size=HOLDOUT_SIZE, random_state=RANDOM_STATE, stratify=y)

    dev_hashes = {hashes[i] for i in dev_idx}
    holdout_hashes = {hashes[i] for i in holdout_idx}
    overlap = dev_hashes & holdout_hashes
    assert len(overlap) == 0, f"Critical leakage detected: {len(overlap)} hashes overlapped!"

    print(f"\n[+] Verified Zero SHA-256 Overlap between Development ({len(dev_idx)}) and Holdout ({len(holdout_idx)})")

    X_dev = X.iloc[dev_idx].reset_index(drop=True)
    X_holdout = X.iloc[holdout_idx].reset_index(drop=True)
    y_dev = y.iloc[dev_idx].reset_index(drop=True)
    y_holdout = y.iloc[holdout_idx].reset_index(drop=True)

    models = [
        (
            lambda: RandomForestClassifier(
                n_estimators=200, max_depth=20, min_samples_split=6, min_samples_leaf=3,
                class_weight="balanced", random_state=42, n_jobs=-1
            ),
            "Random Forest (Baseline)"
        ),
        (
            lambda: HistGradientBoostingClassifier(
                max_iter=200, max_depth=12, min_samples_leaf=10, class_weight="balanced", random_state=42
            ),
            "HistGradientBoosting"
        ),
        (
            lambda: lgb.LGBMClassifier(
                n_estimators=250, max_depth=10, num_leaves=63, learning_rate=0.08,
                class_weight="balanced", random_state=42, n_jobs=-1, verbose=-1
            ),
            "LightGBM"
        )
    ]

    results = []
    for factory, name in models:
        res = evaluate_model_pipeline(factory, name, X_dev, y_dev, X_holdout, y_holdout)
        results.append(res)

    # Save scientific report
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(ARCHIVE_DIR, f"task3-1-real-augmented-{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "real_augmented_report.json")

    report = {
        "experiment": "Task 3.1 & 2.3 Real-World Augmented Training",
        "timestamp": timestamp,
        "data_integrity": integrity,
        "results": results
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[✔] Real Augmented Benchmark Completed! Report saved to:\n    {out_file}\n")


if __name__ == "__main__":
    main()
