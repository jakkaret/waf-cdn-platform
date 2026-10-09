#!/usr/bin/env python3
"""
Leave-one-source-out (LOSO) generalisation check for the latest Gen 3 candidate.

For each source S the model is retrained with the candidate's hyperparameters
on every OTHER source, then scored on S at the candidate's CORE-calibrated
threshold. A source that is only detected when the model has seen that same
source during training is being memorised (dataset artefacts such as the
open-appsec "/?p=<payload>" wrapper), not generalised.

Also reports the wrapper shortcut directly: benign requests shaped like the
open-appsec wrapper (path "/" with exactly one parameter) and how often the
candidate flags them.

Analysis only: nothing here feeds back into training or threshold choice.
"""

import os
import sys
import json

import numpy as np
import joblib
import lightgbm as lgb
from sklearn.metrics import roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, LGBM_PARAMS, build_full_real_dataset, group_folds, weighted_recalls,
)
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS  # noqa: E402
from ml.hybrid_model import TokenModel, make_vectorizer  # noqa: E402


def fit_hybrid(X, H, y, w, meta, alpha, params):
    """Train token model + stacked LightGBM on these rows only (token OOF feeds the tree model)."""
    tok_oof = np.zeros(len(y))
    for fit_idx, val_idx in group_folds(meta):
        tok_oof[val_idx] = TokenModel(alpha).fit(H[fit_idx], y[fit_idx], w[fit_idx]).predict_proba(H[val_idx])
    token = TokenModel(alpha).fit(H, y, w)
    tree = lgb.LGBMClassifier(**params).fit(np.column_stack([X, tok_oof]), y, sample_weight=w)
    return lambda Xt, Ht: tree.predict_proba(np.column_stack([Xt, token.predict_proba(Ht)]))[:, 1]


def latest_candidate():
    cands = sorted(d for d in os.listdir(ARCHIVE_DIR) if d.startswith("task3-1-real-augmented-candidate"))
    for c in reversed(cands):
        rep = os.path.join(ARCHIVE_DIR, c, "experiment_report.json")
        if os.path.exists(rep):
            with open(rep, encoding="utf-8") as f:
                r = json.load(f)
            if "cv" in r and "headline_population" in r.get("holdout_evaluation", {}):
                return c, r
    raise SystemExit("No candidate with a CORE headline found; run train_gen3_full_real_benchmark.py first.")


def main():
    name, report = latest_candidate()
    threshold = report["holdout_evaluation"]["threshold"]
    hp = dict(report["hyperparameters"])
    hp["class_weight"] = {int(k): v for k, v in hp["class_weight"].items()}
    params = LGBM_PARAMS | hp
    print(f"[*] Candidate {name}, threshold {threshold}")

    X, y, _, _, meta = build_full_real_dataset()
    w = meta["Weight"].to_numpy()
    yv = y.to_numpy()
    is_hybrid = "token_model" in report
    if is_hybrid:
        alpha = report["token_model"]["alpha"]
        Xv = X[EXTENDED_FEATURE_COLUMNS].to_numpy(dtype=np.float32)
        H = make_vectorizer().transform(meta["Text"].tolist()).tocsr()
        print(f"[*] Hybrid candidate: token alpha {alpha}, retraining token model + stacking per held-out source")
    results = {}
    for source in sorted(meta["Source"].unique()):
        test = (meta["Source"] == source).to_numpy()
        if is_hybrid:
            train_meta = meta[~test].reset_index(drop=True)
            predict = fit_hybrid(Xv[~test], H[~test], yv[~test], w[~test], train_meta, alpha, params)
            probs = predict(Xv[test], H[test])
        else:
            model = lgb.LGBMClassifier(**params).fit(X[~test], y[~test], sample_weight=w[~test])
            probs = model.predict_proba(X[test])[:, 1]
        r = weighted_recalls(yv[test], (probs >= threshold).astype(int), w[test])
        if len(np.unique(yv[test])) == 2:
            r["roc_auc"] = round(float(roc_auc_score(yv[test], probs, sample_weight=w[test])), 4)
        results[source] = r
        print(f"  held out {source:36s} benign {r['benign_recall']} ({r['benign_shapes']} shapes) | "
              f"attack {r['attack_recall']} ({r['attack_shapes']} shapes)"
              + (f" | AUC {r['roc_auc']}" if "roc_auc" in r else ""), flush=True)

    # Wrapper shortcut: benign "/" requests with exactly one parameter, scored by the candidate itself
    model_file = "hybrid_waf_model.joblib" if is_hybrid else "lightgbm_waf_model.joblib"
    cand_model = joblib.load(os.path.join(ARCHIVE_DIR, name, model_file))
    wrapper_like = ((X["param_count"] == 1) & (X["path_depth"] <= 1) & (yv == 0)).to_numpy()
    if wrapper_like.any():
        if is_hybrid:
            scores = cand_model.predict_proba_frame(X.loc[wrapper_like, EXTENDED_FEATURE_COLUMNS],
                                                    meta.loc[wrapper_like, "Text"].tolist())
        else:
            scores = cand_model.predict_proba(X[wrapper_like])[:, 1]
        flagged = scores >= threshold
        results["_wrapper_shortcut_benign"] = {
            "benign_shapes": round(float(w[wrapper_like].sum()), 1),
            "flagged_share": round(float(w[wrapper_like][flagged].sum() / w[wrapper_like].sum()), 4),
            "note": "benign requests with one parameter at path depth <= 1, scored by the candidate (in-sample for dev rows)",
        }
        print(f"  wrapper-shaped benign: {results['_wrapper_shortcut_benign']}")

    out = os.path.join(ARCHIVE_DIR, name, "leave_source_out.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"threshold": threshold, "results": results}, f, indent=2)
    print(f"[✔] Saved {out}")


if __name__ == "__main__":
    main()
