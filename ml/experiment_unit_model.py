#!/usr/bin/env python3
"""
Experiment: context-free per-unit model (multiple-instance learning) vs the
request-level models, under the trainer's protocol plus two robustness tests.

Motivation (27/09/2026): the request-level hybrid passed the in-distribution
gate but blocked the same command injection only inside the open-appsec
wrapper (POST / p=;cat /etc/shadow -> 1.00) and not at POST /api/run
cmd=... (0.002): payload tokens were confounded with dataset context tokens.
Scoring each unit (path segment, parameter name/value, JSON leaf) on its own
and taking the max removes that context by construction.

Models (all near-duplicate weighted, group split, CORE-calibrated OOF threshold):
  A   LightGBM, 36 structural features
  U   UnitTokenModel (per-unit MIL token model, max over units)
  CU  LightGBM, 36 features + U's out-of-fold score (stacking)
  C   the request-level hybrid candidate from the archive (reference)

Robustness tests (evaluation only; nothing here trains a model):
  1. Context transfer: real attack payload values from HOLDOUT open-appsec
     rows placed into the first parameter of real HOLDOUT benign requests
     (open-appsec legitimate, VPS audit/nginx); the same benign requests
     unchanged are the false-positive control.
  2. The 63 hand-written scenarios of ml/test_comprehensive.py.
Plus leave-one-source-out for U.
"""

import os
import sys
import json
import time
import random
from datetime import datetime
from urllib.parse import parse_qsl, urlencode

import numpy as np
import pandas as pd
import joblib
import lightgbm as lgb
from sklearn.metrics import roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, CORE_SOURCES, EXTERNAL_SOURCES, LGBM_PARAMS, NGINX_BENIGN_PATH, VPS_AUDIT_PATH,
    build_full_real_dataset, choose_threshold_weighted, group_folds, near_duplicate_group,
    split_dev_holdout, weighted_recalls,
)
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request  # noqa: E402
from ml.hybrid_model import Gen3UnitModel, UnitMatrix, UnitTokenModel  # noqa: E402
from ml.test_comprehensive import TESTS  # noqa: E402

STRESS_N = 1500


def oof_unit(um, rows, y, w, meta_rows, alpha):
    oof = np.zeros(len(rows))
    for fit_idx, val_idx in group_folds(meta_rows):
        m = UnitTokenModel(alpha).fit_matrix(um, rows[fit_idx], y[fit_idx], w[fit_idx])
        oof[val_idx] = m.predict_matrix(um, rows[val_idx])
    return oof


def core_threshold(y, p, w, core):
    return choose_threshold_weighted(y[core], p[core], w[core])


def holdout_metrics(y, p, w, meta, thr):
    core = meta["Source"].isin(CORE_SOURCES).to_numpy()
    pred = (p >= thr).astype(int)
    return {
        "core": weighted_recalls(y[core], pred[core], w[core])
        | {"auc": round(float(roc_auc_score(y[core], p[core], sample_weight=w[core])), 4)},
        "all": weighted_recalls(y, pred, w) | {"auc": round(float(roc_auc_score(y, p, sample_weight=w)), 4)},
        "per_source": {s: weighted_recalls(y[i], pred[i], w[i]) for s, i in meta.groupby("Source").indices.items()},
    }


def fmt(name, oof_cal, hm):
    c = hm["core"]
    return (f"[{name}] OOF core attack {oof_cal['attack_recall']*100:.2f}% @ benign {oof_cal['benign_recall']*100:.2f}% "
            f"(thr {oof_cal['threshold']:.4f}) | HOLDOUT core benign {c['benign_recall']*100:.2f}% "
            f"attack {c['attack_recall']*100:.2f}% AUC {c['auc']} | all benign {hm['all']['benign_recall']*100:.2f}% "
            f"attack {hm['all']['attack_recall']*100:.2f}%")


def _payload_value(row):
    for q in (row.get("GET-Query", ""), row.get("POST-Data", "")):
        for k, v in parse_qsl(q, keep_blank_values=True):
            if k == "p" and v:
                return v
    return None


def build_stress_set(holdout_groups):
    """Real payloads from holdout attack rows injected into real holdout benign contexts."""
    rng = random.Random(20260927)
    payloads = []
    if not os.path.exists(EXTERNAL_SOURCES["OpenAppSec_Malicious"]):
        print("[!] Stress set skipped: open-appsec payloads not prepared (ml/prepare_external_datasets.py --download)")
        return [], [], [], []
    with open(EXTERNAL_SOURCES["OpenAppSec_Malicious"], encoding="utf-8") as fp:
        for line in fp:
            r = json.loads(line)
            if near_duplicate_group(r["URI"], r["GET-Query"], r["POST-Data"]) in holdout_groups:
                v = _payload_value(r)
                if v:
                    payloads.append((v, r["Family"]))
    contexts = []
    for path in (EXTERNAL_SOURCES["OpenAppSec_Legitimate"], VPS_AUDIT_PATH, NGINX_BENIGN_PATH):
        if not os.path.exists(path):  # private VPS files are absent on a public-data-only run
            continue
        with open(path, encoding="utf-8") as fp:
            for line in fp:
                r = json.loads(line)
                if r.get("Class", "Valid") != "Valid" or str(r.get("Method", "GET")).upper() != "GET":
                    continue
                q = r.get("GET-Query", "")
                if not q or "=" not in q:
                    continue
                if near_duplicate_group(r["URI"], q, r.get("POST-Data", "")) in holdout_groups:
                    contexts.append((r["URI"], q, os.path.basename(path)))
    rng.shuffle(payloads)
    rng.shuffle(contexts)
    n = min(STRESS_N, len(payloads), len(contexts))
    injected, control, families, ctx_src = [], [], [], []
    for (payload, fam), (uri, q, src) in zip(payloads[:n], contexts[:n]):
        pairs = parse_qsl(q, keep_blank_values=True)
        pairs[0] = (pairs[0][0], payload)
        injected.append(("GET", f"{uri}?{urlencode(pairs)}", ""))
        control.append(("GET", f"{uri}?{q}", ""))
        families.append(fam)
        ctx_src.append(src)
    print(f"[*] Stress set: {n} injected + {n} control (payload pool {len(payloads)}, context pool {len(contexts)})")
    return injected, control, families, ctx_src


def score_requests(scorer, requests):
    return np.array([scorer(m, u, b) for m, u, b in requests])


def stress_report(name, scorer, thr, injected, control, families):
    if not injected:
        return {"skipped": "no stress set"}
    pi, pc = score_requests(scorer, injected), score_requests(scorer, control)
    det = pi >= thr
    by_fam = pd.Series(det).groupby(pd.Series(families)).mean().round(4).to_dict()
    out = {"detection_rate": round(float(det.mean()), 4), "control_false_positive_rate": round(float((pc >= thr).mean()), 4),
           "by_family": by_fam}
    print(f"  [{name} STRESS] detect {out['detection_rate']*100:.2f}% | control FP {out['control_false_positive_rate']*100:.2f}% | {by_fam}")
    return out


def scenario_report(name, scorer, thr):
    ok_allow = ok_block = n_allow = n_block = 0
    misses = []
    for expected, method, url, body, desc in TESTS:
        blocked = scorer(method, url, body) >= thr
        if expected == "ALLOW":
            n_allow += 1
            ok_allow += not blocked
        else:
            n_block += 1
            ok_block += blocked
        if blocked != (expected == "BLOCK"):
            misses.append(f"{expected}:{desc}")
    out = {"normal_allowed": f"{ok_allow}/{n_allow}", "attack_blocked": f"{ok_block}/{n_block}", "misses": misses}
    print(f"  [{name} SCENARIOS] normal {out['normal_allowed']} | attack {out['attack_blocked']} | misses {misses}")
    return out


def main():
    X, y, _, _, meta = build_full_real_dataset()
    yv, w = y.to_numpy(), meta["Weight"].to_numpy()
    dev, hold = split_dev_holdout(meta)
    meta_dev, meta_hold = meta.iloc[dev].reset_index(drop=True), meta.iloc[hold].reset_index(drop=True)
    core_dev = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    Xv = X[EXTENDED_FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    report = {}

    t = time.time()
    um = UnitMatrix(meta["Units"].tolist())
    print(f"[*] Unit matrix {um.H.shape}, nnz {um.H.nnz:,} in {time.time()-t:.0f}s", flush=True)

    # Reference LightGBM params from the latest hybrid candidate
    cands = sorted(d for d in os.listdir(ARCHIVE_DIR) if d.startswith("task3-1-real-augmented-candidate"))
    hybrid_dir = next(c for c in reversed(cands) if os.path.exists(os.path.join(ARCHIVE_DIR, c, "hybrid_waf_model.joblib")))
    with open(os.path.join(ARCHIVE_DIR, hybrid_dir, "experiment_report.json"), encoding="utf-8") as f:
        hrep = json.load(f)
    hp = dict(hrep["hyperparameters"])
    hp["class_weight"] = {int(k): v for k, v in hp["class_weight"].items()}
    lgb_params = LGBM_PARAMS | hp
    hybrid = joblib.load(os.path.join(ARCHIVE_DIR, hybrid_dir, "hybrid_waf_model.joblib"))
    report["reference_hybrid_candidate"] = hybrid_dir

    # U: alpha on CORE dev OOF
    best = None
    for alpha in (1e-7, 3e-7, 1e-6, 3e-6):
        t = time.time()
        oof = oof_unit(um, dev, yv[dev], w[dev], meta_dev, alpha)
        cal = core_threshold(yv[dev], oof, w[dev], core_dev)
        print(f"  unit alpha={alpha:g} -> CORE OOF attack {cal['attack_recall']*100:.2f}% @ benign "
              f"{cal['benign_recall']*100:.2f}% [{time.time()-t:.0f}s]", flush=True)
        if best is None or cal["attack_recall"] > best[0]["attack_recall"]:
            best = (cal, alpha, oof)
    cal_u, alpha_u, oof_u = best
    unit_model = UnitTokenModel(alpha_u).fit_matrix(um, dev, yv[dev], w[dev])
    p_u_hold = unit_model.predict_matrix(um, hold)
    hm_u = holdout_metrics(yv[hold], p_u_hold, w[hold], meta_hold, cal_u["threshold"])
    print(fmt(f"U alpha={alpha_u:g}", cal_u, hm_u), flush=True)
    report["U_unit_model"] = {"alpha": alpha_u, "oof_core": cal_u, "holdout": hm_u}

    # A: 36-feature LightGBM
    oof_a = np.zeros(len(dev))
    for fi, vi in group_folds(meta_dev):
        oof_a[vi] = lgb.LGBMClassifier(**lgb_params).fit(Xv[dev][fi], yv[dev][fi], sample_weight=w[dev][fi]).predict_proba(Xv[dev][vi])[:, 1]
    cal_a = core_threshold(yv[dev], oof_a, w[dev], core_dev)
    model_a = lgb.LGBMClassifier(**lgb_params).fit(Xv[dev], yv[dev], sample_weight=w[dev])
    hm_a = holdout_metrics(yv[hold], model_a.predict_proba(Xv[hold])[:, 1], w[hold], meta_hold, cal_a["threshold"])
    print(fmt("A lightgbm-36", cal_a, hm_a), flush=True)
    report["A_lightgbm_36"] = {"oof_core": cal_a, "holdout": hm_a}

    # CU: stacking U's OOF score under LightGBM
    Xcu_dev = np.column_stack([Xv[dev], oof_u])
    Xcu_hold = np.column_stack([Xv[hold], p_u_hold])
    oof_cu = np.zeros(len(dev))
    for fi, vi in group_folds(meta_dev):
        oof_cu[vi] = lgb.LGBMClassifier(**lgb_params).fit(Xcu_dev[fi], yv[dev][fi], sample_weight=w[dev][fi]).predict_proba(Xcu_dev[vi])[:, 1]
    cal_cu = core_threshold(yv[dev], oof_cu, w[dev], core_dev)
    model_cu = lgb.LGBMClassifier(**lgb_params).fit(Xcu_dev, yv[dev], sample_weight=w[dev])
    hm_cu = holdout_metrics(yv[hold], model_cu.predict_proba(Xcu_hold)[:, 1], w[hold], meta_hold, cal_cu["threshold"])
    print(fmt("CU stacked-unit", cal_cu, hm_cu), flush=True)
    report["CU_stacked_unit"] = {"oof_core": cal_cu, "holdout": hm_cu}

    # Robustness tests
    unit_serving = Gen3UnitModel(unit_model, cal_u["threshold"])

    def score_a(m, u, b):
        f = extract_features_from_request(url=u, method=m, body=b)
        return float(model_a.predict_proba(pd.DataFrame([f])[EXTENDED_FEATURE_COLUMNS].to_numpy(dtype=np.float32))[0, 1])

    def score_cu(m, u, b):
        f = extract_features_from_request(url=u, method=m, body=b)
        us = unit_serving.score_request(m, u, b)
        row = np.append(pd.DataFrame([f])[EXTENDED_FEATURE_COLUMNS].to_numpy(dtype=np.float32)[0], us)
        return float(model_cu.predict_proba(row.reshape(1, -1))[0, 1])

    scorers = {
        "A": (score_a, cal_a["threshold"]),
        "C_hybrid": (hybrid.score_request, hybrid.threshold),
        "U": (unit_serving.score_request, cal_u["threshold"]),
        "CU": (score_cu, cal_cu["threshold"]),
    }
    print("\n[*] Context-transfer stress test (evaluation only)")
    injected, control, families, _ = build_stress_set(set(meta_hold["Group"]))
    report["stress_context_transfer"] = {k: stress_report(k, s, t_, injected, control, families) for k, (s, t_) in scorers.items()}
    print("\n[*] 63 hand-written scenarios (test_comprehensive.py)")
    report["scenarios"] = {k: scenario_report(k, s, t_) for k, (s, t_) in scorers.items()}

    print("\n[*] Leave-one-source-out for U (threshold from U's CORE OOF)")
    loso = {}
    all_rows = np.arange(len(yv))
    for source in sorted(meta["Source"].unique()):
        test = (meta["Source"] == source).to_numpy()
        m = UnitTokenModel(alpha_u).fit_matrix(um, all_rows[~test], yv[~test], w[~test])
        p = m.predict_matrix(um, all_rows[test])
        r = weighted_recalls(yv[test], (p >= cal_u["threshold"]).astype(int), w[test])
        if len(np.unique(yv[test])) == 2:
            r["auc"] = round(float(roc_auc_score(yv[test], p, sample_weight=w[test])), 4)
        loso[source] = r
        print(f"  [U LOSO] {source:36s} benign {r['benign_recall']} | attack {r['attack_recall']}"
              + (f" | AUC {r['auc']}" if "auc" in r else ""), flush=True)
    report["U_unit_model"]["loso"] = loso

    out_dir = os.path.join(ARCHIVE_DIR, f"experiment-unit-model-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "unit_model_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=float)
    joblib.dump({"unit": unit_serving, "cu_lgbm": model_cu, "cu_threshold": cal_cu["threshold"]},
                os.path.join(out_dir, "unit_models.joblib"))
    print(f"[✔] Saved {out_dir}")


if __name__ == "__main__":
    main()
