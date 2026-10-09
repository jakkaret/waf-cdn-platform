#!/usr/bin/env python3
"""
Experiment: do value-level detector features (ml/value_features.py) raise
attack recall *robustly*, i.e. outside the dataset contexts they were trained on?

Why (27/09/2026 hybrid candidate): in-distribution family recall is already
~99%, yet leave-one-source-out attack recall is 6-13%, the 63 scenarios block
18/26 attacks and `POST /api/run cmd=;cat /etc/shadow` scores 0.002. The
LightGBM's top importances are context features (query_body_entropy,
url_path_entropy, avg/max_param_length, path_depth). So each configuration is
judged on four things, not on the in-distribution gate alone:

  1. CORE holdout gate (same protocol as the trainer: group split, near-duplicate
     weights, threshold from CORE dev out-of-fold only) + per-family recall and
     recall split by "request carries any attack signal" vs "structural only"
  2. context-transfer stress test (real holdout payloads inside real holdout
     benign requests; evaluation only) from ml/experiment_unit_model.py
  3. the 63 scenarios of ml/test_comprehensive.py
  4. leave-one-dataset-out (skip with --no-loso): AUC and attack recall at 98.5%
     benign on the unseen dataset (threshold-free), plus benign and attack
     recall at a threshold chosen on the training datasets only
Metrics 1-3 are repeated over --folds group-level holdout folds (mean ± std).
Each configuration is also scored against promotion gate 3.1-G.0
(ml/promotion_gate.py: every dataset weighted equally).

Configurations (LightGBM, hyperparameters of the latest archived candidate):
  A  36 structural features (baseline)
  B  36 + value features
  C  B with +1 monotone constraints on every attack-signal feature, so a
     payload can never be "explained away" by benign-looking context
  D  C without the context-fingerprint features (CONTEXT_COLUMNS)
  E  D without monotone constraints; E_plus_<feature> puts one context
     feature back (ablation); D_plus_query_body_entropy likewise for D.
     Default run: A, B, D, E, E_plus_query_body_entropy, D_plus_query_body_entropy.

Nothing here changes the training data: no synthetic rows, the stress set is
never trained on.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.experiment_unit_model import (  # noqa: E402
    build_stress_set, holdout_metrics, scenario_report, stress_report,
)
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request  # noqa: E402
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, BUILD_CACHE_DIR, CORE_SOURCES, LGBM_PARAMS, _build_cache_key, _sha256_file,
    build_full_real_dataset, choose_threshold_weighted, group_folds, weighted_recalls,
)
from ml.gen3_model import FEATURE_SET_VERSION, FEATURE_SETS  # noqa: E402
from ml.promotion_gate import dataset_of, evaluate as evaluate_gate, format_gate  # noqa: E402
from ml.value_features import (  # noqa: E402
    VALUE_FEATURE_COLUMNS, VALUE_MONOTONE_COLUMNS, extract_value_features, extract_value_features_from_units,
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))

# Request-shape features that mostly identify the source dataset (top importances
# of the 20260927-205652 candidate); removed in configuration D.
CONTEXT_COLUMNS = [
    "url_path_entropy", "query_body_entropy", "avg_param_length", "max_param_length", "path_depth", "param_count",
]
# Existing structural features that only ever count attack evidence.
SIGNAL_COLUMNS = [
    "keyword_matches", "html_tag_matches", "path_traversal_depth", "has_sql_operator", "has_ssrf_token",
    "has_ssti_nosql", "inline_function_count", "comment_token_count", "suspicious_path_marker_count",
    "encoded_attack_token_count", "double_encoded_count", "json_operator_count",
]
MONOTONE = set(SIGNAL_COLUMNS) | set(VALUE_MONOTONE_COLUMNS)

NO_CONTEXT_COLUMNS = [c for c in EXTENDED_FEATURE_COLUMNS if c not in CONTEXT_COLUMNS] + VALUE_FEATURE_COLUMNS

CONFIGS = {
    "A_base36": (EXTENDED_FEATURE_COLUMNS, False),
    "B_36_plus_value": (EXTENDED_FEATURE_COLUMNS + VALUE_FEATURE_COLUMNS, False),
    "C_value_monotone": (EXTENDED_FEATURE_COLUMNS + VALUE_FEATURE_COLUMNS, True),
    "D_no_context_monotone": (NO_CONTEXT_COLUMNS, True),
    # 28/09 run: C < B everywhere, so monotone constraints cost accuracy; D's
    # robustness came from dropping the context features. E = D unconstrained.
    "E_no_context": (NO_CONTEXT_COLUMNS, False),
    # Ablation: E plus one context feature back, to separate features carrying
    # real signal (D lost 8.7pp LFI and 7pp CSIC) from dataset fingerprints.
    **{f"E_plus_{c}": (NO_CONTEXT_COLUMNS + [c], False) for c in CONTEXT_COLUMNS},
    # D (monotone, no context) was the most robust on 28/09; qbe itself stays unconstrained
    "D_plus_query_body_entropy": (NO_CONTEXT_COLUMNS + ["query_body_entropy"], True),
    # 29/09: F without encoded_char_ratio, the top driver of GoTestWAF benign false positives
    "F_noenc": (FEATURE_SETS["F-noenc"], False),
}
# 28/09 scrutiny: the single-split, fixed-threshold comparisons could not separate
# B / D / E / E_plus_query_body_entropy; rerun them over several folds with
# threshold-free leave-one-dataset-out metrics.
DEFAULT_CONFIGS = ["A_base36", "B_36_plus_value", "D_no_context_monotone", "E_no_context",
                   "E_plus_query_body_entropy", "D_plus_query_body_entropy"]


def value_feature_frame(meta):
    """Value features for every built row, cached next to the trainer's build cache."""
    key = hashlib.sha256((_build_cache_key() + _sha256_file(os.path.join(ML_DIR, "value_features.py"))).encode())
    path = os.path.join(BUILD_CACHE_DIR, f"value_{key.hexdigest()[:24]}.joblib")
    if os.path.exists(path):
        print(f"[+] Loaded value features from cache {os.path.relpath(path, ML_DIR)}")
        return joblib.load(path)
    t0 = time.time()
    rows = [extract_value_features_from_units(units, uri) for units, uri in zip(meta["Units"], meta["URI"])]
    V = pd.DataFrame(rows, columns=VALUE_FEATURE_COLUMNS).astype(np.float32)
    print(f"[+] Value features for {len(V)} rows in {time.time() - t0:.0f}s")
    for old in (p for p in os.listdir(BUILD_CACHE_DIR) if p.startswith("value_")):
        os.remove(os.path.join(BUILD_CACHE_DIR, old))
    joblib.dump(V, path)
    return V


def latest_hyperparameters():
    """LightGBM params of the newest archived candidate (the trainer's dev-OOF choice), else the defaults."""
    cands = sorted(d for d in os.listdir(ARCHIVE_DIR) if d.startswith("task3-1-real-augmented-candidate"))
    for c in reversed(cands):
        path = os.path.join(ARCHIVE_DIR, c, "experiment_report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                hp = json.load(f).get("hyperparameters")
            if hp:
                hp = dict(hp)
                hp["class_weight"] = {int(k): v for k, v in hp["class_weight"].items()}
                return LGBM_PARAMS | hp, c
    return dict(LGBM_PARAMS), "defaults"


def make_params(base, columns, monotone):
    if not monotone:
        return base
    return base | {"monotone_constraints": [1 if c in MONOTONE else 0 for c in columns],
                   "monotone_constraints_method": "intermediate"}


def per_family(y, pred, w, meta):
    att = y == 1
    out = {}
    for fam, idx in meta[att].groupby("Family").indices.items():
        rows = np.flatnonzero(att)[idx]
        out[fam] = {"rows": len(rows), "attack_recall": round(float(w[rows][pred[rows] == 1].sum() / w[rows].sum()), 4)}
    return out


def signal_split(y, pred, w, has_signal, core):
    """CORE holdout attack recall for requests with / without any attack signal at all."""
    out = {}
    for name, m in (("with_signal", has_signal), ("structural_only", ~has_signal)):
        sel = core & (y == 1) & m
        out[name] = {"attack_shapes": round(float(w[sel].sum()), 1),
                     "attack_recall": round(float(w[sel & (pred == 1)].sum() / w[sel].sum()), 4) if sel.any() else None}
    return out


def request_matrix(method, url, body, columns):
    parts = urlsplit(url)
    feats = extract_features_from_request(url=url, method=method, body=body)
    feats |= extract_value_features(method, parts.path or "/", parts.query, body)
    return np.array([[feats[c] for c in columns]], dtype=np.float32)


def evaluate_fold(name, columns, params, Xc, yv, w, has_signal_all, meta, dev, hold, stress):
    """Trainer protocol on one group-level dev/holdout split: CORE dev-OOF threshold, holdout evaluated once."""
    t0 = time.time()
    meta_dev, meta_hold = meta.iloc[dev].reset_index(drop=True), meta.iloc[hold].reset_index(drop=True)
    core_dev = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    core_hold = meta_hold["Source"].isin(CORE_SOURCES).to_numpy()
    Xd, yd, wd = Xc[dev], yv[dev], w[dev]
    oof = np.zeros(len(dev))
    for fi, vi in group_folds(meta_dev):
        oof[vi] = lgb.LGBMClassifier(**params).fit(Xd[fi], yd[fi], sample_weight=wd[fi]).predict_proba(Xd[vi])[:, 1]
    cal = choose_threshold_weighted(yd[core_dev], oof[core_dev], wd[core_dev])
    thr = cal["threshold"]
    model = lgb.LGBMClassifier(**params).fit(Xd, yd, sample_weight=wd)
    p_hold = model.predict_proba(Xc[hold])[:, 1]
    pred_hold = (p_hold >= thr).astype(int)
    hm = holdout_metrics(yv[hold], p_hold, w[hold], meta_hold, thr)
    c = hm["core"]
    print(f"[{name}] OOF core attack {cal['attack_recall']*100:.2f}% @ benign {cal['benign_recall']*100:.2f}% "
          f"(thr {thr:.4f}) | HOLDOUT core benign {c['benign_recall']*100:.2f}% attack {c['attack_recall']*100:.2f}% "
          f"AUC {c['auc']} [{time.time()-t0:.0f}s]", flush=True)
    entry = {
        "oof_core": cal, "holdout": hm,
        "holdout_per_family": per_family(yv[hold], pred_hold, w[hold], meta_hold),
        "holdout_core_signal_split": signal_split(yv[hold], pred_hold, w[hold], has_signal_all[hold], core_hold),
        "feature_gain": {k: round(float(v), 1) for k, v in sorted(
            zip(columns, model.booster_.feature_importance("gain")), key=lambda kv: -kv[1])},
    }

    def scorer(m, u, b):
        return float(model.predict_proba(request_matrix(m, u, b, columns))[0, 1])

    entry["stress_context_transfer"] = stress_report(name, scorer, thr, *stress)
    entry["scenarios"] = scenario_report(name, scorer, thr)
    return entry, model, thr


def attack_recall_at_benign(y, p, w, benign_target=0.985):
    """Weighted attack recall at the best threshold keeping `benign_target` of benign weight below it."""
    return choose_threshold_weighted(y, p, w, benign_target)["attack_recall"]


def leave_one_family_out(name, params, Xc, yv, w, meta):
    """Train without one dataset, score it. Separates ranking from calibration:

    - auc and attack_recall_at_benign_98_5: threshold-free on the held-out data,
      i.e. what a per-tenant tuned threshold (WORKING_RULES rollout: silent ->
      tuning -> enforce) could reach;
    - at_training_threshold: benign AND attack recall at a threshold chosen on
      the training datasets only (group-level 80/20 split of them), i.e. an
      untuned deployment. A single threshold from another model, as in the
      28/09 runs, mixed score shift into "generalisation".
    """
    # A whole dataset leaves at once (dataset_of joins open-appsec's benign and attack
    # sources), so each held-out unit carries both classes where the dataset has them.
    fam = meta["Source"].map(dataset_of).to_numpy()
    out = {}
    for held in sorted(set(fam)):
        test = fam == held
        train_rows = np.flatnonzero(~test)
        if len(np.unique(yv[train_rows])) < 2:
            continue
        fit_i, cal_i = next(group_folds(meta.iloc[train_rows].reset_index(drop=True)))
        fit_rows, cal_rows = train_rows[fit_i], train_rows[cal_i]
        m = lgb.LGBMClassifier(**params).fit(Xc[fit_rows], yv[fit_rows], sample_weight=w[fit_rows])
        thr = choose_threshold_weighted(yv[cal_rows], m.predict_proba(Xc[cal_rows])[:, 1], w[cal_rows])["threshold"]
        p = m.predict_proba(Xc[test])[:, 1]
        r = {"threshold_from_training_datasets": round(thr, 4),
             "at_training_threshold": weighted_recalls(yv[test], (p >= thr).astype(int), w[test])}
        if len(np.unique(yv[test])) == 2:
            r["auc"] = round(float(roc_auc_score(yv[test], p, sample_weight=w[test])), 4)
            r["attack_recall_at_benign_98_5"] = round(attack_recall_at_benign(yv[test], p, w[test]), 4)
            r["attack_recall_at_benign_99_9"] = round(attack_recall_at_benign(yv[test], p, w[test], 0.999), 4)
        out[held] = r
        t = r["at_training_threshold"]
        print(f"  [{name} LOFO] {held:20s} AUC {r.get('auc')} | attack@benign98.5 {r.get('attack_recall_at_benign_98_5')} | "
              f"training thr: benign {t['benign_recall']} attack {t['attack_recall']}", flush=True)
    return out


def _mean_std(values):
    vals = [v for v in values if v is not None]
    return {"mean": round(float(np.mean(vals)), 4), "std": round(float(np.std(vals)), 4)} if vals else None


def summarize(folds):
    """Mean and spread over holdout folds of the metrics the decision rests on."""
    def get(f, *path):
        for k in path:
            f = f.get(k) if isinstance(f, dict) else None
        return f
    metrics = {
        "core_benign": ("holdout", "core", "benign_recall"), "core_attack": ("holdout", "core", "attack_recall"),
        "core_auc": ("holdout", "core", "auc"), "all_attack": ("holdout", "all", "attack_recall"),
        "lfi": ("holdout_per_family", "LFI", "attack_recall"), "sqli": ("holdout_per_family", "SQLi", "attack_recall"),
        "stress_detect": ("stress_context_transfer", "detection_rate"),
        "stress_control_fp": ("stress_context_transfer", "control_false_positive_rate"),
    }
    out = {k: _mean_std([get(f, *p) for f in folds]) for k, p in metrics.items()}
    out["scenario_attack_blocked"] = _mean_std([int(f["scenarios"]["attack_blocked"].split("/")[0]) for f in folds])
    out["scenario_normal_allowed"] = _mean_std([int(f["scenarios"]["normal_allowed"].split("/")[0]) for f in folds])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-loso", action="store_true", help="skip leave-one-dataset-out")
    ap.add_argument("--folds", type=int, default=3, help="holdout folds to repeat the evaluation on (1-5)")
    ap.add_argument("--only-lofo", action="store_true", help="skip the holdout folds, run leave-one-dataset-out only")
    ap.add_argument("--configs", default=",".join(DEFAULT_CONFIGS), help="comma-separated subset of " + ",".join(CONFIGS))
    args = ap.parse_args()
    configs = {k: CONFIGS[k] for k in args.configs.split(",")}

    X, y, _, integrity, meta = build_full_real_dataset()
    V = value_feature_frame(meta)
    F = pd.concat([X.reset_index(drop=True).astype(np.float32), V], axis=1)
    yv, w = y.to_numpy(), meta["Weight"].to_numpy()
    has_signal = (F[SIGNAL_COLUMNS].to_numpy() > 0).any(axis=1) | (V["v_detector_units"].to_numpy() > 0)
    base_params, params_from = latest_hyperparameters()
    print(f"[*] LightGBM params from {params_from}; sources present: {sorted(meta['Source'].unique())}")
    print(f"[*] Attack rows with any value-detector hit: "
          f"{(V['v_detector_units'].to_numpy()[yv == 1] > 0).mean()*100:.1f}% (benign {(V['v_detector_units'].to_numpy()[yv == 0] > 0).mean()*100:.2f}%)")

    # Same group-level folds as the trainer; fold 0 is the trainer's holdout
    splits = [] if args.only_lofo else list(group_folds(meta))[:max(1, min(args.folds, 5))]
    stress_sets = []
    for k, (_, hold) in enumerate(splits):
        print(f"\n[*] Fold {k}: building context-transfer stress set (evaluation only)")
        stress_sets.append(build_stress_set(set(meta.iloc[hold]["Group"]))[:3])

    report = {"params_from": params_from, "sources": sorted(meta["Source"].unique()),
              "feature_extraction": FEATURE_SET_VERSION,
              "core_sources_present": sorted(set(CORE_SOURCES) & set(meta["Source"])), "holdout_folds": len(splits),
              "integrity": {k: integrity[k] for k in ("total_unique_samples", "effective_distinct_shapes",
                                                      "unique_rows_by_source")},
              "configs": {}}
    models = {}
    for name, (columns, monotone) in configs.items():
        print(f"\n{'='*70}\n {name}: {len(columns)} features, monotone={monotone}\n{'='*70}", flush=True)
        params = make_params(base_params, columns, monotone)
        Xc = F[columns].to_numpy(dtype=np.float32)
        folds = []
        for k, (dev, hold) in enumerate(splits):
            entry, model, thr = evaluate_fold(f"{name} f{k}", columns, params, Xc, yv, w, has_signal, meta, dev, hold,
                                              stress_sets[k])
            folds.append(entry)
            if k == 0:
                models[name] = {"model": model, "columns": columns, "threshold": thr}
        report["configs"][name] = {"n_features": len(columns), "monotone": monotone,
                                   "summary": summarize(folds) if folds else {}, "folds": folds}
        if not args.no_loso:
            report["configs"][name]["leave_one_dataset_out"] = leave_one_family_out(name, params, Xc, yv, w, meta)
        report["configs"][name]["gate"] = evaluate_gate(folds, report["configs"][name].get("leave_one_dataset_out"))

    def ms(d, pct=True):
        return f"{d['mean']*100:5.1f}±{d['std']*100:3.1f}" if pct and d else (f"{d['mean']:4.1f}" if d else "  n/a")

    print(f"\n{'='*70}\n SUMMARY over {len(splits)} holdout folds (mean ± std, weighted recall %)\n{'='*70}")
    print(f" {'config':30s} {'CORE ben':>10s} {'CORE att':>10s} {'LFI':>10s} {'stress':>10s} {'scen att':>8s}"
          "   leave-one-dataset-out: AUC / attack@benign98.5 / (training-thr benign, attack)")
    for name, e in report["configs"].items():
        s = {k: None for k in ("core_benign", "core_attack", "lfi", "stress_detect", "scenario_attack_blocked")} | e["summary"]
        lofo = "  ".join(
            f"{h}: {r.get('auc')}/{r.get('attack_recall_at_benign_98_5')}/"
            f"({r['at_training_threshold']['benign_recall']}, {r['at_training_threshold']['attack_recall']})"
            for h, r in e.get("leave_one_dataset_out", {}).items())
        print(f" {name:30s} {ms(s['core_benign']):>10s} {ms(s['core_attack']):>10s} {ms(s['lfi']):>10s} "
              f"{ms(s['stress_detect']):>10s} {ms(s['scenario_attack_blocked'], pct=False):>8s}   {lofo}")

    print(f"\n{'='*70}\n PROMOTION GATE 3.1-G.0 (this run only; ml/promotion_gate.py combines runs)\n{'='*70}")
    for name, e in report["configs"].items():
        print(format_gate(name, e["gate"]))

    out_dir = os.path.join(ARCHIVE_DIR, f"experiment-value-features-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "value_feature_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=float)
    joblib.dump(models, os.path.join(out_dir, "value_feature_models.joblib"))
    print(f"\n[✔] Saved {out_dir}")


if __name__ == "__main__":
    main()
