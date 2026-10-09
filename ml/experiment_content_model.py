#!/usr/bin/env python3
"""
Experiment: content (token) model vs the 36-feature LightGBM, same protocol.

Why: leave-one-source-out showed the 36 count features + trees learn where
signals sit per dataset (e.g. "attacks carry parameters") rather than what
the payload is, so SR-BH path-embedded SQLi scored 7% when SR-BH was unseen.
A token model reads the decoded request itself and is location-agnostic.

Models, all with near-duplicate weights, the trainer's group-level split,
CORE-calibrated threshold from dev out-of-fold probabilities, holdout scored
once, and leave-one-source-out (LOSO):
  A  LightGBM on EXTENDED_FEATURE_COLUMNS (reference, from the latest candidate)
  B  hashed token unigrams+bigrams (letters, digits, each punctuation char) ->
     TF-IDF -> logistic regression (SGD)
  C  LightGBM on the 36 features + B's out-of-fold score (stacking)

Local experiment only; writes ml/models/archive/<experiment dir>/content_model_report.json.
"""

import os
import sys
import json
import time
from datetime import datetime

import numpy as np
import lightgbm as lgb
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, CORE_SOURCES, LGBM_PARAMS, build_full_real_dataset, choose_threshold_weighted,
    group_folds, split_dev_holdout, weighted_recalls,
)

TOKEN_PATTERN = r"[a-z]+|\d+|[^\sa-z\d]"
HASH_FEATURES = 2 ** 20


def vectorizer():
    return HashingVectorizer(token_pattern=TOKEN_PATTERN, ngram_range=(1, 2), n_features=HASH_FEATURES,
                             alternate_sign=False, norm=None, lowercase=False, dtype=np.float32)


class TokenModel:
    """Hashed token n-grams -> TF-IDF (fit on training rows) -> weighted logistic regression."""

    def __init__(self, alpha):
        self.alpha = alpha

    def fit(self, H, y, w):
        self.tfidf = TfidfTransformer(sublinear_tf=True).fit(H)
        self.clf = SGDClassifier(loss="log_loss", alpha=self.alpha, max_iter=30, tol=1e-4,
                                 random_state=42).fit(self.tfidf.transform(H), y, sample_weight=w)
        return self

    def predict_proba(self, H):
        return self.clf.predict_proba(self.tfidf.transform(H))[:, 1]


def oof_scores(make_model, M, y, meta):
    oof = np.zeros(len(y))
    w = meta["Weight"].to_numpy()
    for fit_idx, val_idx in group_folds(meta):
        oof[val_idx] = make_model().fit(M[fit_idx], y[fit_idx], w[fit_idx]).predict_proba(M[val_idx])
    return oof


class LGBMWrap:
    def __init__(self, params):
        self.params = params

    def fit(self, X, y, w):
        self.m = lgb.LGBMClassifier(**self.params).fit(X, y, sample_weight=w)
        return self

    def predict_proba(self, X):
        return self.m.predict_proba(X)[:, 1]


def evaluate(name, make_model, M_dev, y_dev, meta_dev, M_hold, y_hold, meta_hold):
    """OOF-calibrate on CORE dev, fit on dev, score holdout once."""
    t0 = time.time()
    oof = oof_scores(make_model, M_dev, y_dev, meta_dev)
    core_d = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    w_dev = meta_dev["Weight"].to_numpy()
    cal = choose_threshold_weighted(y_dev[core_d], oof[core_d], w_dev[core_d])
    model = make_model().fit(M_dev, y_dev, w_dev)
    p = model.predict_proba(M_hold)
    thr = cal["threshold"]
    w_h = meta_hold["Weight"].to_numpy()
    core_h = meta_hold["Source"].isin(CORE_SOURCES).to_numpy()
    pred = (p >= thr).astype(int)
    out = {
        "oof_core": {"threshold": round(thr, 4), "attack_recall": round(cal["attack_recall"], 4),
                     "benign_recall": round(cal["benign_recall"], 4),
                     "auc": round(float(roc_auc_score(y_dev[core_d], oof[core_d], sample_weight=w_dev[core_d])), 4)},
        "holdout_core": weighted_recalls(y_hold[core_h], pred[core_h], w_h[core_h])
                        | {"auc": round(float(roc_auc_score(y_hold[core_h], p[core_h], sample_weight=w_h[core_h])), 4)},
        "holdout_all": weighted_recalls(y_hold, pred, w_h)
                       | {"auc": round(float(roc_auc_score(y_hold, p, sample_weight=w_h)), 4)},
        "holdout_per_source": {s: weighted_recalls(y_hold[idx], pred[idx], w_h[idx])
                               for s, idx in meta_hold.groupby("Source").indices.items()},
        "seconds": round(time.time() - t0, 1),
    }
    print(f"[{name}] OOF core: attack {out['oof_core']['attack_recall']*100:.2f}% @ benign "
          f"{out['oof_core']['benign_recall']*100:.2f}% (thr {thr:.4f}, AUC {out['oof_core']['auc']}) | "
          f"HOLDOUT core: benign {out['holdout_core']['benign_recall']*100:.2f}% attack "
          f"{out['holdout_core']['attack_recall']*100:.2f}% AUC {out['holdout_core']['auc']} | "
          f"all: benign {out['holdout_all']['benign_recall']*100:.2f}% attack {out['holdout_all']['attack_recall']*100:.2f}% "
          f"[{out['seconds']}s]", flush=True)
    return out, oof, model, thr


def loso(name, make_model, M, y, meta, threshold):
    """Train on all other sources, score the held-out source (AUC + recall at the model's CORE threshold)."""
    w = meta["Weight"].to_numpy()
    res = {}
    for source in sorted(meta["Source"].unique()):
        test = (meta["Source"] == source).to_numpy()
        p = make_model().fit(M[~test], y[~test], w[~test]).predict_proba(M[test])
        r = weighted_recalls(y[test], (p >= threshold).astype(int), w[test])
        if len(np.unique(y[test])) == 2:
            r["auc"] = round(float(roc_auc_score(y[test], p, sample_weight=w[test])), 4)
        res[source] = r
        print(f"  [{name} LOSO] {source:36s} benign {r['benign_recall']} | attack {r['attack_recall']}"
              + (f" | AUC {r['auc']}" if "auc" in r else ""), flush=True)
    return res


def latest_lgbm_params():
    cands = sorted(d for d in os.listdir(ARCHIVE_DIR) if d.startswith("task3-1-real-augmented-candidate"))
    for c in reversed(cands):
        path = os.path.join(ARCHIVE_DIR, c, "experiment_report.json")
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        if "headline_population" in r.get("holdout_evaluation", {}):
            hp = dict(r["hyperparameters"])
            hp["class_weight"] = {int(k): v for k, v in hp["class_weight"].items()}
            return c, LGBM_PARAMS | hp
    raise SystemExit("run train_gen3_full_real_benchmark.py first")


def main():
    X, y, _, _, meta = build_full_real_dataset()
    yv = y.to_numpy()
    dev, hold = split_dev_holdout(meta)
    meta_dev, meta_hold = meta.iloc[dev].reset_index(drop=True), meta.iloc[hold].reset_index(drop=True)
    cand, lgb_params = latest_lgbm_params()
    report = {"reference_candidate": cand, "token_pattern": TOKEN_PATTERN, "hash_features": HASH_FEATURES}

    t = time.time()
    H = vectorizer().transform(meta["Text"].tolist()).tocsr()
    print(f"[*] Hashed token matrix {H.shape}, nnz {H.nnz:,} in {time.time()-t:.0f}s", flush=True)

    # B: pick regularisation on CORE dev OOF only
    best = None
    for alpha in (1e-6, 3e-6, 1e-5):
        out, oof, _, thr = evaluate(f"B alpha={alpha}", lambda a=alpha: TokenModel(a), H[dev], yv[dev], meta_dev,
                                    H[hold], yv[hold], meta_hold)
        key = (out["oof_core"]["attack_recall"], out["oof_core"]["auc"])
        if best is None or key > best[0]:
            best = (key, alpha, out, oof, thr)
    _, alpha, out_b, oof_b, thr_b = best
    report["B_token_model"] = {"alpha": alpha, **out_b}

    # A: reference LightGBM under the identical protocol
    Xv = X.to_numpy(dtype=np.float32)
    out_a, _, _, thr_a = evaluate("A lightgbm-36", lambda: LGBMWrap(lgb_params), Xv[dev], yv[dev], meta_dev,
                                  Xv[hold], yv[hold], meta_hold)
    report["A_lightgbm_36"] = out_a

    # C: stacking - token OOF score as the 37th LightGBM feature (holdout gets the dev-fitted token score)
    tok_full_dev = TokenModel(alpha).fit(H[dev], yv[dev], meta_dev["Weight"].to_numpy())
    Xc_dev = np.column_stack([Xv[dev], oof_b])
    Xc_hold = np.column_stack([Xv[hold], tok_full_dev.predict_proba(H[hold])])
    out_c, _, _, thr_c = evaluate("C stacked", lambda: LGBMWrap(lgb_params), Xc_dev, yv[dev], meta_dev,
                                  Xc_hold, yv[hold], meta_hold)
    report["C_stacked"] = out_c

    print("\n[*] Leave-one-source-out (AUC is threshold-free; recall at each model's CORE threshold)")
    report["B_token_model"]["loso"] = loso("B", lambda: TokenModel(alpha), H, yv, meta, thr_b)

    out_dir = os.path.join(ARCHIVE_DIR, f"experiment-content-model-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "content_model_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[✔] Saved {out_dir}/content_model_report.json")


if __name__ == "__main__":
    main()
