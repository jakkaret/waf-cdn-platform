#!/usr/bin/env python3
"""
Roadmap Task 2.4 + 2.3 Integration:
Benchmark LightGBM and HistGradientBoosting on CSIC-only clean dataset
(ZERO synthetic samples, 100% SHA-256 deduplicated, 5-fold CV + unseen holdout).
Directly tests whether Gradient Boosting breaks the ~65% attack recall ceiling on CSIC.
"""

import os
import sys
import json
import hashlib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import roc_auc_score, confusion_matrix
import lightgbm as lgb
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.benchmark_real_holdout import load_real_csic_dataset, prepare_features, choose_threshold, MIN_BENIGN_RECALL, MIN_ATTACK_RECALL, HOLDOUT_SIZE, N_SPLITS, RANDOM_STATE

ARCHIVE_DIR = os.path.join(os.path.dirname(__file__), "models", "archive")


def run_csic_benchmark(model_factory, model_name):
    df_clean = load_real_csic_dataset()
    X, y, hashes, integrity = prepare_features(df_clean)

    row_indices = np.arange(len(X))
    dev_idx, holdout_idx = train_test_split(
        row_indices, test_size=HOLDOUT_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    dev_hashes = {hashes[i] for i in dev_idx}
    holdout_hashes = {hashes[i] for i in holdout_idx}
    assert len(dev_hashes & holdout_hashes) == 0, "Holdout leakage detected!"

    X_dev, y_dev = X.iloc[dev_idx].reset_index(drop=True), y.iloc[dev_idx].reset_index(drop=True)
    X_holdout, y_holdout = X.iloc[holdout_idx].reset_index(drop=True), y.iloc[holdout_idx].reset_index(drop=True)

    print(f"\n{'='*20} CSIC-Only Benchmark: {model_name} {'='*20}")
    print(f"[*] Development: {len(X_dev)} rows | Unseen Holdout: {len(X_holdout)} rows (0 leakage)")

    # 5-Fold Stratified CV on Development Set
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
    print(f"[*] 5-Fold CV Mean Threshold: {mean_threshold:.4f} | Avg Benign Recall: {np.mean(cv_benign_recalls)*100:.2f}% | Avg Attack Recall: {np.mean(cv_attack_recalls)*100:.2f}%")

    # Fit on all Dev, evaluate on Unseen Holdout
    final_model = model_factory()
    final_model.fit(X_dev, y_dev)
    holdout_probs = final_model.predict_proba(X_holdout)[:, 1]

    # Evaluate at mean CV threshold
    holdout_preds = (holdout_probs >= mean_threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_holdout, holdout_preds).ravel()
    b_rec = tn / (tn + fp)
    a_rec = tp / (tp + fn)
    auc = float(roc_auc_score(y_holdout, holdout_probs))

    print(f"[*] UNSEEN HOLDOUT RESULTS (Zero Synthetic Rows):")
    print(f"    - ROC-AUC:       {auc:.4f}")
    print(f"    - Benign Recall: {b_rec*100:.2f}% (Safety Target >= 98.5%)")
    print(f"    - Attack Recall: {a_rec*100:.2f}% (Goal >= 85%)")
    print(f"    - Confusion:     TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    return {
        "model": model_name,
        "mean_cv_threshold": round(mean_threshold, 4),
        "cv_benign_recall_avg": round(float(np.mean(cv_benign_recalls)), 4),
        "cv_attack_recall_avg": round(float(np.mean(cv_attack_recalls)), 4),
        "holdout": {
            "roc_auc": round(auc, 4),
            "benign_recall": round(b_rec, 4),
            "attack_recall": round(a_rec, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "passed_safety_gate": bool(b_rec >= MIN_BENIGN_RECALL and a_rec >= MIN_ATTACK_RECALL)
        }
    }


def main():
    experiments = [
        (
            lambda: RandomForestClassifier(
                n_estimators=200, max_depth=20, min_samples_split=6, min_samples_leaf=3,
                class_weight="balanced", random_state=42, n_jobs=-1
            ),
            "Random Forest (Task 2.4 Baseline)"
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

    all_results = []
    for factory, name in experiments:
        res = run_csic_benchmark(factory, name)
        all_results.append(res)

    exp_dir = os.path.join(ARCHIVE_DIR, "task2-3-csic-holdout-benchmark")
    os.makedirs(exp_dir, exist_ok=True)
    out_file = os.path.join(exp_dir, "csic_comparison_report.json")
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[+] CSIC Holdout Benchmark comparison saved to: {out_file}\n")


if __name__ == "__main__":
    main()
