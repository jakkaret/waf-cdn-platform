#!/usr/bin/env python3
"""
Train the Gen 3 serving model (feature set F, ml/gen3_model.py) on ALL data.

The experiments (ml/experiment_value_features.py) hold data back to measure the
model; this script builds the model to deploy once the feature set is chosen:

1. Same dataset as the experiments (build_full_real_dataset + value features),
   same LightGBM hyperparameters (latest archived candidate).
2. Threshold from 5-fold group-level out-of-fold scores over all data: the
   lowest threshold at which EVERY dataset keeps at least --benign-target of its
   benign traffic (default 99%, a margin over the 98.5% of gate G1 because a
   threshold set exactly at the target lands on either side of it on new data).
3. Out-of-fold benign / attack recall per dataset at that threshold (honest
   estimates of G1 / G2 for this model), the 63 scenarios, single-request latency.
4. Final fit on all rows; saves gen3_f_model.joblib (Gen3FModel) and
   model_card.json (inputs with sha256, code hashes, git commit, metrics) to
   ml/models/archive/gen3-final-<feature set>-<timestamp>/ (--feature-set, default F).
5. gen3_f_model.onnx next to it (ml/gen3_onnx.py), written only if ONNX and
   LightGBM agree within 1e-5 on 50,000 training rows, the scenarios and
   threshold-boundary rows; the result is in the card under "onnx".

Unseen-dataset recall (gate G3/G4) and the stress test are properties of the
feature set measured by the experiment; the card cites that report.

Not for production enforcement: gate 3.1-G.0 is not passed (3/5). Use for demos
and shadow scoring (ml_api.py /predict-gen3) only.
"""

import argparse
import glob
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.experiment_value_features import latest_hyperparameters, value_feature_frame  # noqa: E402
from ml.gen3_model import FEATURE_SETS, Gen3FModel, feature_set_version  # noqa: E402
from ml.promotion_gate import GATE, dataset_of  # noqa: E402
from ml.test_comprehensive import TESTS  # noqa: E402
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, CSIC_PATH, EXTERNAL_SOURCES, NGINX_BENIGN_PATH, TELEMETRY_DIR, VPS_AUDIT_PATH, _sha256_file,
    build_full_real_dataset, group_folds, weighted_recalls,
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
REFERENCE_EXPERIMENT = "experiment-value-features-20260928-144424"  # gate v2 run that selected F


def benign_threshold(p_benign, w_benign, target):
    """Lowest t with weighted benign recall (score < t) >= target."""
    order = np.argsort(-p_benign, kind="stable")
    pb, wb = p_benign[order], w_benign[order]
    above = np.cumsum(wb) / wb.sum()
    k = int(np.searchsorted(above, (1.0 - target) + 1e-12, side="right"))
    return 0.0 if k >= len(pb) else float(np.nextafter(pb[k], np.inf))


def classification_metrics(y, pred, w=None):
    """Precision / recall / F1 with attack (1) as the positive class.

    w: near-duplicate group weights (as every other metric here); None = one per row.
    Precision and F1 depend on the attack/benign mix of the data they are computed on.
    """
    w = np.ones(len(y)) if w is None else np.asarray(w, dtype=float)
    y, pred = np.asarray(y), np.asarray(pred)
    tp, fp = float(w[(y == 1) & (pred == 1)].sum()), float(w[(y == 0) & (pred == 1)].sum())
    fn, tn = float(w[(y == 1) & (pred == 0)].sum()), float(w[(y == 0) & (pred == 0)].sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fn else None)
    r4 = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"precision": r4(precision), "recall": r4(recall), "f1": r4(f1),
            "tp": r4(tp), "fp": r4(fp), "fn": r4(fn), "tn": r4(tn)}


def fmt_metrics(m):
    pct = lambda v: "   n/a" if v is None else f"{v * 100:6.2f}%"  # noqa: E731
    return f"Precision {pct(m['precision'])} | Recall {pct(m['recall'])} | F1 {pct(m['f1'])}"


def per_dataset(y, p, w, datasets, threshold):
    out = {}
    for d in sorted(set(datasets)):
        m = datasets == d
        r = weighted_recalls(y[m], (p[m] >= threshold).astype(int), w[m])
        out[d] = {k: r[k] for k in ("benign_recall", "benign_shapes", "attack_recall", "attack_shapes")}
    return out


def export_onnx_artifact(wrapper, F, card, out_dir):
    """Write gen3_f_model.onnx to out_dir if it passes the parity check; returns the card's "onnx" entry.

    Never raises: the joblib model is saved regardless, and a failure is reported loudly.
    """
    try:
        from ml.gen3_onnx import Gen3OnnxModel, export_onnx
        rng = np.random.default_rng(0)
        rows = np.vstack([F[rng.choice(len(F), min(len(F), 50_000), replace=False)],
                          wrapper.matrix([(m, u, b) for _, m, u, b, _ in TESTS])])
        data, report = export_onnx(wrapper, rows, card)
        if not report["parity_passed"]:
            print(f"[!] ONNX parity FAILED ({report}); gen3_f_model.onnx not written")
            return report | {"exported": False}
        served = Gen3OnnxModel(data)
        lat = []
        for _, m, u, b, _ in TESTS * 5:
            t = time.perf_counter()
            served.score_request(m, u, b)
            lat.append((time.perf_counter() - t) * 1000)
        path = os.path.join(out_dir, "gen3_f_model.onnx")
        with open(path, "wb") as f:
            f.write(data)
        print(f"[*] ONNX parity max |diff| real {report['parity_max_abs_diff_real_rows']:.2e} / boundary "
              f"{report['parity_max_abs_diff_boundary_rows']:.2e}; p50 {np.percentile(lat, 50):.2f} ms")
        return report | {"exported": True, "file": "gen3_f_model.onnx", "sha256": _sha256_file(path), "bytes": len(data),
                         "latency_single_request": {"p50_ms": round(float(np.percentile(lat, 50)), 2),
                                                    "p95_ms": round(float(np.percentile(lat, 95)), 2), "n": len(lat)}}
    except Exception as exc:
        print(f"[!] ONNX export failed, joblib model is still saved: {type(exc).__name__}: {exc}")
        return {"exported": False, "error": f"{type(exc).__name__}: {exc}"}


def git_commit():
    try:
        return subprocess.check_output(["git", "-C", ML_DIR, "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--benign-target", type=float, default=0.99,
                    help="benign recall every dataset must keep at the threshold (gate G1 is 0.985)")
    ap.add_argument("--feature-set", default="F", choices=sorted(FEATURE_SETS),
                    help="named column set of ml/gen3_model.FEATURE_SETS to train")
    ap.add_argument("--exclude-dataset", action="append", default=[], metavar="NAME",
                    help="drop a dataset (name as in promotion_gate.dataset_of, e.g. OpenAppSec) before training; "
                         "for a model that is then evaluated on that dataset's public benchmark (repeatable)")
    args = ap.parse_args()
    cols, version = FEATURE_SETS[args.feature_set], feature_set_version(args.feature_set)

    X, y, _, integrity, meta = build_full_real_dataset()
    V = value_feature_frame(meta)
    if args.exclude_dataset:
        present = sorted(set(meta["Source"].map(dataset_of)))
        unknown = sorted(set(args.exclude_dataset) - set(present))
        if unknown:
            raise SystemExit(f"--exclude-dataset {unknown}: not in the built data {present}")
        keep = ~meta["Source"].map(dataset_of).isin(args.exclude_dataset).to_numpy()
        X, y, V = X[keep].reset_index(drop=True), y[keep].reset_index(drop=True), V[keep].reset_index(drop=True)
        meta = meta[keep].reset_index(drop=True)
        print(f"[*] excluded {args.exclude_dataset}: {int((~keep).sum())} rows dropped, {int(keep.sum())} kept")
    F = pd.concat([X.reset_index(drop=True).astype(np.float32), V], axis=1)[cols].to_numpy(dtype=np.float32)
    yv, w = y.to_numpy(), meta["Weight"].to_numpy()
    datasets = meta["Source"].map(dataset_of).to_numpy()
    params, params_from = latest_hyperparameters()
    print(f"[*] {len(yv)} rows, {len(cols)} features ({version}); params from {params_from}")

    # 1. out-of-fold scores over all data
    t0 = time.time()
    oof = np.zeros(len(yv))
    for fold, (fit, val) in enumerate(group_folds(meta), 1):
        oof[val] = lgb.LGBMClassifier(**params).fit(F[fit], yv[fit], sample_weight=w[fit]).predict_proba(F[val])[:, 1]
        print(f"  OOF fold {fold}/5 done [{time.time()-t0:.0f}s]", flush=True)

    # 2. threshold: every dataset keeps --benign-target of its benign traffic
    per_ds_thr = {d: benign_threshold(oof[(datasets == d) & (yv == 0)], w[(datasets == d) & (yv == 0)], args.benign_target)
                  for d in sorted(set(datasets)) if ((datasets == d) & (yv == 0)).any()}
    threshold = max(per_ds_thr.values())
    oof_by_ds = per_dataset(yv, oof, w, datasets, threshold)
    known = [r["attack_recall"] for r in oof_by_ds.values() if r["attack_recall"] is not None]
    benign = [r["benign_recall"] for r in oof_by_ds.values() if r["benign_recall"] is not None]
    print(f"[*] Threshold {threshold:.4f} (binding: {max(per_ds_thr, key=per_ds_thr.get)}; per dataset {per_ds_thr})")
    for d, r in oof_by_ds.items():
        print(f"    OOF {d:20s} benign {r['benign_recall']} | attack {r['attack_recall']}")
    print(f"    G1-style min benign {min(benign):.4f} (gate {GATE['benign_min']}) | "
          f"G2-style mean attack {np.mean(known):.4f} (gate {GATE['known_attack_mean']})")
    oof_pred = (oof >= threshold).astype(int)
    oof_metrics = {"all_datasets": classification_metrics(yv, oof_pred, w)}
    oof_metrics |= {d: classification_metrics(yv[datasets == d], oof_pred[datasets == d], w[datasets == d])
                    for d in sorted(set(datasets))}
    print("[*] Out-of-fold Precision / Recall / F1 (attack = positive, group-weighted):")
    for d, m in oof_metrics.items():
        print(f"    {d:20s} {fmt_metrics(m)}")

    # 3. final fit on all rows
    model = lgb.LGBMClassifier(**params).fit(F, yv, sample_weight=w)
    wrapper = Gen3FModel(model, threshold, feature_set=args.feature_set)

    scenario_results = []
    for exp, m, u, b, desc in TESTS:
        score = wrapper.score_request(m, u, b)
        predicted = "BLOCK" if score >= threshold else "ALLOW"
        scenario_results.append({"scenario": desc, "method": m, "expected": exp, "predicted": predicted,
                                 "score": round(score, 4), "correct": predicted == exp})
    n_allow = sum(1 for r in scenario_results if r["expected"] == "ALLOW")
    n_block = len(scenario_results) - n_allow
    normal_ok = sum(1 for r in scenario_results if r["expected"] == "ALLOW" and r["correct"])
    attack_ok = sum(1 for r in scenario_results if r["expected"] == "BLOCK" and r["correct"])
    misses = [f"{r['expected']}:{r['scenario']}" for r in scenario_results if not r["correct"]]
    scenario_metrics = classification_metrics(np.array([r["expected"] == "BLOCK" for r in scenario_results], dtype=int),
                                              np.array([r["predicted"] == "BLOCK" for r in scenario_results], dtype=int))
    print(f"\n[*] Scenarios (threshold {threshold:.4f})")
    print(f"    {'#':>3}  {'expected':8s} {'predicted':9s} {'score':>7s}  ok  scenario")
    for i, r in enumerate(scenario_results, 1):
        print(f"    {i:3d}  {r['expected']:8s} {r['predicted']:9s} {r['score']:7.4f}  {'✓' if r['correct'] else '✗'}   "
              f"{r['scenario']}")
    print(f"    normal allowed {normal_ok}/{n_allow} | attack blocked {attack_ok}/{n_block}")
    print(f"    Scenario {fmt_metrics(scenario_metrics)}  (TP {scenario_metrics['tp']:.0f} FP {scenario_metrics['fp']:.0f} "
          f"FN {scenario_metrics['fn']:.0f} TN {scenario_metrics['tn']:.0f})\n")

    reqs = [(m, u, b) for _, m, u, b, _ in TESTS] * 5
    wrapper.score_request(*reqs[0])  # warm-up
    lat = []
    for r in reqs:
        t = time.perf_counter()
        wrapper.score_request(*r)
        lat.append((time.perf_counter() - t) * 1000)
    latency = {"p50_ms": round(float(np.percentile(lat, 50)), 2), "p95_ms": round(float(np.percentile(lat, 95)), 2),
               "n": len(lat)}
    print(f"[*] Single-request latency p50 {latency['p50_ms']} ms / p95 {latency['p95_ms']} ms")

    # 4. save model + card
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = args.feature_set.lower() + "".join(f"-no{d.lower()}" for d in sorted(args.exclude_dataset))
    out_dir = os.path.join(ARCHIVE_DIR, f"gen3-final-{tag}-{stamp}")
    os.makedirs(out_dir, exist_ok=True)
    inputs = [CSIC_PATH, VPS_AUDIT_PATH, NGINX_BENIGN_PATH, *EXTERNAL_SOURCES.values()] + \
        sorted(glob.glob(os.path.join(TELEMETRY_DIR, "*.jsonl")))
    card = {
        "model": "Gen3FModel: LightGBM on feature set F, trained on all data"
                 + (f" except {sorted(args.exclude_dataset)}" if args.exclude_dataset else ""),
        "status": "NOT PROMOTED - promotion gate 3.1-G.0 passed 3/5 (see reference_experiment); demo / shadow use only",
        "created": stamp, "git_commit": git_commit(),
        "feature_set": version, "feature_columns": cols,
        "threshold": round(threshold, 6), "benign_target_per_dataset": args.benign_target,
        "threshold_per_dataset": {d: round(t, 6) for d, t in per_ds_thr.items()},
        "hyperparameters": {k: v for k, v in params.items() if k != "class_weight"}
        | {"class_weight": {str(k): v for k, v in params["class_weight"].items()}, "from": params_from},
        "out_of_fold_at_threshold": oof_by_ds,
        "out_of_fold_gate_estimates": {"G1_min_benign": round(min(benign), 4), "G2_mean_known_attack": round(float(np.mean(known)), 4)},
        "out_of_fold_metrics": oof_metrics,
        "scenarios": {"normal_allowed": f"{normal_ok}/{n_allow}", "attack_blocked": f"{attack_ok}/{n_block}", "misses": misses,
                      "metrics": scenario_metrics, "results": scenario_results},
        "latency_single_request": latency,
        "reference_experiment": {"report": REFERENCE_EXPERIMENT, "config": "E_plus_query_body_entropy",
                                 "gate_v2": "G1 98.69 PASS, G2 83.6 FAIL, G3 61.1 FAIL, G4 41.0 PASS, G5 PASS"},
        "data": {"sources": sorted(meta["Source"].unique()), "rows": int(len(yv)),
                 "excluded_datasets": sorted(args.exclude_dataset),
                 "integrity": {k: integrity[k] for k in ("total_unique_samples", "effective_distinct_shapes", "unique_rows_by_source")},
                 "input_files": {os.path.relpath(p, ML_DIR): {"sha256": _sha256_file(p), "bytes": os.path.getsize(p)}
                                 for p in inputs if os.path.exists(p)}},
        "code_sha256": {f: _sha256_file(os.path.join(ML_DIR, f)) for f in
                        ("gen3_model.py", "gen3_onnx.py", "value_features.py", "feature_engineering.py", "hybrid_model.py",
                         "train_final_gen3.py", "train_gen3_full_real_benchmark.py")},
        "environment": {"python": platform.python_version(), "lightgbm": lgb.__version__},
    }
    card["onnx"] = export_onnx_artifact(wrapper, F, card, out_dir)
    wrapper.card = card
    joblib.dump(wrapper, os.path.join(out_dir, "gen3_f_model.joblib"))
    with open(os.path.join(out_dir, "model_card.json"), "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2, default=float)
    print(f"\n[✔] Saved {out_dir}\n    serve it: copy gen3_f_model.onnx (or .joblib) to ml/models/gen3/ "
          f"(ml_api.py /predict-gen3 prefers ONNX)")


if __name__ == "__main__":
    main()
