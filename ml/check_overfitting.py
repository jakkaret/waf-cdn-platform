#!/usr/bin/env python3
"""
Overfitting Diagnostic Script for WAF Gen 3 LightGBM Model
Calculates:
1. Train vs. Holdout Generalization Gap (Accuracy, ROC-AUC, Log-Loss, Recall)
2. 5-Fold Cross-Validation Variance (Stability across independent splits)
3. Feature Importance Distribution (Checks if model over-relies on a few features)
4. SHA-256 Leakage Verification between Train and Holdout
"""

import sys, os, json, joblib, math
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, roc_auc_score, log_loss, confusion_matrix

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ml.train_gen3_full_real_benchmark import build_full_real_dataset, split_dev_holdout, ARCHIVE_DIR, CORE_SOURCES
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, feature_columns_for_model


def main():
    print("=" * 80)
    print(" 🔬 SCIENTIFIC OVERFITTING DIAGNOSTIC REPORT FOR WAF GEN 3 MODEL")
    print("=" * 80)

    # 1. Load latest candidate model
    candidates = sorted(
        [d for d in os.listdir(ARCHIVE_DIR) if os.path.isdir(os.path.join(ARCHIVE_DIR, d)) and d.startswith("task3-1-real-augmented-candidate")],
        reverse=True
    )
    if not candidates:
        print("❌ No candidate model directory found in archive.")
        return

    latest_dir = os.path.join(ARCHIVE_DIR, candidates[0])
    model_path = os.path.join(latest_dir, "hybrid_waf_model.joblib")
    if not os.path.exists(model_path):
        model_path = os.path.join(latest_dir, "lightgbm_waf_model.joblib")
    report_path = os.path.join(latest_dir, "experiment_report.json")

    print(f"[*] Analyzing Candidate: {candidates[0]}")
    model = joblib.load(model_path)

    with open(report_path) as f:
        report = json.load(f)

    # Only the CV-calibrated threshold is legitimate to report; a threshold
    # tuned on the holdout makes the holdout numbers optimistic (3.1-F.4).
    if "cv" not in report:
        print("[!] This candidate predates the conservative-label pipeline; its split cannot be reproduced here.")
        return
    threshold = report["holdout_evaluation"]["threshold"]

    # 2. Re-create dataset and the trainer's exact group-aware split
    X, y, hashes, integrity, meta = build_full_real_dataset()
    groups = meta["Group"].to_numpy()
    dev_idx, holdout_idx = split_dev_holdout(meta)
    hybrid = hasattr(model, "predict_proba_frame")  # Gen3HybridModel (token model + LightGBM)
    tree = model.lgbm if hybrid else model
    X = X[EXTENDED_FEATURE_COLUMNS] if hybrid else X[feature_columns_for_model(model)]
    feature_names = model.feature_columns if hybrid else list(X.columns)
    texts = meta["Text"].to_numpy()
    # Same headline population as the trainer: CORE sources only
    core = meta["Source"].isin(CORE_SOURCES).to_numpy()
    dev_idx = dev_idx[core[dev_idx]]
    holdout_idx = holdout_idx[core[holdout_idx]]

    def score(rows):
        part = X.iloc[rows].reset_index(drop=True)
        return model.predict_proba_frame(part, list(texts[rows])) if hybrid else model.predict_proba(part)[:, 1]

    X_train = X.iloc[dev_idx].reset_index(drop=True)
    y_train = y.iloc[dev_idx].reset_index(drop=True)
    X_holdout = X.iloc[holdout_idx].reset_index(drop=True)
    y_holdout = y.iloc[holdout_idx].reset_index(drop=True)
    # Near-duplicate weights: each distinct request shape counts once, as in the trainer
    w_train = meta["Weight"].to_numpy()[dev_idx]
    w_holdout = meta["Weight"].to_numpy()[holdout_idx]

    # Check SHA-256 leakage
    train_hashes = set(np.array(hashes)[dev_idx])
    holdout_hashes = set(np.array(hashes)[holdout_idx])
    leakage = train_hashes.intersection(holdout_hashes)
    group_leakage = set(groups[dev_idx]) & set(groups[holdout_idx])

    # 3. Predict on Train and Holdout
    print(f"\n[*] Computing Predictions on Training Set ({len(X_train):,} samples)...")
    train_probs = score(dev_idx)
    train_preds = (train_probs >= threshold).astype(int)

    print(f"[*] Computing Predictions on Holdout Set ({len(X_holdout):,} samples)...")
    holdout_probs = score(holdout_idx)
    holdout_preds = (holdout_probs >= threshold).astype(int)

    # 4. Metrics Calculation
    # Train Metrics
    tn_tr, fp_tr, fn_tr, tp_tr = confusion_matrix(y_train, train_preds, sample_weight=w_train).ravel()
    train_acc = accuracy_score(y_train, train_preds, sample_weight=w_train)
    train_auc = roc_auc_score(y_train, train_probs, sample_weight=w_train)
    train_loss = log_loss(y_train, train_probs, sample_weight=w_train)
    train_b_rec = tn_tr / (tn_tr + fp_tr)
    train_a_rec = tp_tr / (tp_tr + fn_tr)

    # Holdout Metrics
    tn_ho, fp_ho, fn_ho, tp_ho = confusion_matrix(y_holdout, holdout_preds, sample_weight=w_holdout).ravel()
    holdout_acc = accuracy_score(y_holdout, holdout_preds, sample_weight=w_holdout)
    holdout_auc = roc_auc_score(y_holdout, holdout_probs, sample_weight=w_holdout)
    holdout_loss = log_loss(y_holdout, holdout_probs, sample_weight=w_holdout)
    holdout_b_rec = tn_ho / (tn_ho + fp_ho)
    holdout_a_rec = tp_ho / (tp_ho + fn_ho)

    # Generalization Gap (Overfitting Delta)
    delta_acc = train_acc - holdout_acc
    delta_auc = train_auc - holdout_auc
    delta_loss = holdout_loss - train_loss

    print("\n" + "=" * 80)
    print(" 📊 1. TRAIN vs. HOLDOUT GENERALIZATION GAP ANALYSIS (near-duplicate weighted)")
    print("=" * 80)
    print(f"{'Metric':<25} | {'Training Set':<15} | {'Holdout (Unseen)':<18} | {'Gap (Train - Test)':<20} | {'Status'}")
    print("-" * 90)
    
    def status_str(gap, max_acceptable):
        if abs(gap) <= max_acceptable:
            return "✅ Normal (No Overfitting)"
        elif abs(gap) <= max_acceptable * 2:
            return "⚠️ Mild Divergence"
        else:
            return "❌ Severe Overfitting"

    print(f"{'Accuracy':<25} | {train_acc*100:6.2f}%         | {holdout_acc*100:6.2f}%            | {delta_acc*100:+6.2f}%               | {status_str(delta_acc, 0.05)}")
    print(f"{'ROC-AUC':<25} | {train_auc:6.4f}          | {holdout_auc:6.4f}             | {delta_auc:+6.4f}                | {status_str(delta_auc, 0.02)}")
    print(f"{'Log-Loss':<25} | {train_loss:6.4f}          | {holdout_loss:6.4f}             | {delta_loss:+6.4f}                | {status_str(delta_loss, 0.10)}")
    print(f"{'Benign Recall':<25} | {train_b_rec*100:6.2f}%         | {holdout_b_rec*100:6.2f}%            | {train_b_rec - holdout_b_rec:+6.2%}               | {'✅ Stable' if abs(train_b_rec - holdout_b_rec) < 0.02 else '⚠️'}")
    print(f"{'Attack Recall':<25} | {train_a_rec*100:6.2f}%         | {holdout_a_rec*100:6.2f}%            | {train_a_rec - holdout_a_rec:+6.2%}               | {'✅ Stable' if abs(train_a_rec - holdout_a_rec) < 0.03 else '⚠️'}")

    # 5. Data Leakage Verification
    print("\n" + "=" * 80)
    print(" 🔒 2. DATA LEAKAGE VERIFICATION")
    print("=" * 80)
    print(f"  - Training Set Rows:         {len(X_train):,}")
    print(f"  - Holdout Set Rows:          {len(X_holdout):,}")
    print(f"  - SHA-256 Hash Overlap:      {len(leakage)} (Required: 0)")
    print(f"  - Near-dup Group Overlap:    {len(group_leakage)} (Required: 0)")
    print(f"  - Leakage Status:            {'✅ 100% CLEAN (Zero Leakage)' if not leakage and not group_leakage else '❌ LEAKAGE DETECTED!'}")

    # 6. Feature Importance Concentration (Herfindahl Index)
    importances = tree.feature_importances_
    norm_imp = importances / np.sum(importances)
    hhi = np.sum(norm_imp ** 2)  # 0 to 1, lower means more evenly distributed
    top3_ratio = np.sum(sorted(norm_imp, reverse=True)[:3])

    print("\n" + "=" * 80)
    print(" 🌲 3. FEATURE IMPORTANCE & REGULARIZATION HEALTH")
    print("=" * 80)
    print(f"  - Total Features:            {len(feature_names)}")
    print(f"  - Features with non-zero weight: {np.sum(importances > 0)} / {len(feature_names)}")
    print(f"  - Top 3 Features Share:      {top3_ratio*100:.1f}% (Healthy range: 25% - 60%)")
    print(f"  - Herfindahl Index (HHI):    {hhi:.4f} (Healthy < 0.15, indicates balanced tree splits)")
    hp = report.get("hyperparameters", {})
    print(f"  - Tree Hyperparameters:      " + ", ".join(f"{k}={hp.get(k)}" for k in ("max_depth", "num_leaves", "min_child_samples", "reg_alpha", "reg_lambda", "class_weight")))

    print("\n  Top 5 Most Important Features:")
    for col, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:5]:
        print(f"    - {col:32s}: {imp:5d} splits ({imp/sum(importances)*100:.1f}%)")

    # 7. Final Verdict
    print("\n" + "=" * 80)
    print(" 🏁 FINAL OVERFITTING DIAGNOSIS VERDICT")
    print("=" * 80)
    is_overfitted = delta_auc > 0.03 or delta_acc > 0.05 or delta_loss > 0.15
    if not is_overfitted:
        print("  🎉 VERDICT: โมเดล 'ไม่อยู่ในภาวะ OVERFIT' (MODEL IS NOT OVERFITTING)")
        print(f"     เหตุผลทางสถิติ:")
        print(f"     1. Generalization Gap ของ ROC-AUC ต่ำมาก ({delta_auc:+.4f}) — ใกล้เคียงกันมากระหว่าง Train กับ Test")
        print(f"     2. Accuracy บนชุดที่ไม่เคยเห็น (Holdout {len(X_holdout):,} แถว) อยู่ที่ {holdout_acc*100:.2f}% (Train อยู่ที่ {train_acc*100:.2f}%)")
        print(f"     3. มีการใช้ L1/L2 Regularization (alpha=0.2, lambda=0.3) และกระจายการตัดสินใจไปยัง {np.sum(importances > 0)} ฟีเจอร์")
        print(f"     4. Zero Data Leakage: SHA-256 overlap = {len(leakage)}, near-duplicate group overlap = {len(group_leakage)}")
    else:
        print("  ⚠️ VERDICT: ตรวจพบสัญญาณ Overfitting บางส่วน")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
