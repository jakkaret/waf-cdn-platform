"""Offline: convert the /predict forests from .joblib to pickle-free .npz
(ml/plain_forest.py, audit H52) and check they match sklearn exactly.

    PYTHONPATH=. python -m ml.export_plain_models

joblib.load runs a pickle: run this only on artifacts this repository's
training scripts produced. Serving (ml/ml_api.py) loads only the .npz.
"""
import argparse
import os

import joblib
import numpy as np
import pandas as pd

from ml.attribution import compute_forest_attribution
from ml.feature_engineering import extract_features_from_request
from ml.plain_forest import (PlainIsolationForest, PlainRandomForest,
                             export_isolation_forest, export_random_forest)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
SAMPLES = [
    ("/", "GET", ""), ("/search?q=<script>alert(1)</script>", "GET", ""),
    ("/item?id=1' OR '1'='1", "GET", ""), ("/../../etc/passwd", "GET", ""),
    ("/api/login", "POST", "user=admin&pass=secret"), ("/t?n={{7*7}}", "GET", ""),
    ("/upload", "POST", "A" * 5000), ("/products/42/reviews?page=2&sort=asc", "GET", ""),
]


def check(rf, iso, prf, piso, rows):
    worst = 0.0
    for values in rows:
        df = pd.DataFrame([values], columns=prf.feature_names)
        p, bias, contrib = prf.explain(values)
        sk_p = rf.predict_proba(df)[0][1]
        sk_bias, sk_contrib = compute_forest_attribution(rf, df)
        assert prf.predict(values) == rf.predict(df)[0]
        worst = max(worst, abs(p - sk_p), abs(bias - sk_bias),
                    max(abs(contrib[f] - sk_contrib[f]) for f in contrib),
                    abs(piso.decision_function(values) - iso.decision_function(df)[0]))
    return worst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", default=MODELS_DIR)
    ap.add_argument("--random-rows", type=int, default=2000)
    args = ap.parse_args()
    rf = joblib.load(os.path.join(args.models_dir, "random_forest_waf.joblib"))
    iso = joblib.load(os.path.join(args.models_dir, "isolation_forest_waf.joblib"))
    rf_out = os.path.join(args.models_dir, "random_forest_waf.npz")
    iso_out = os.path.join(args.models_dir, "isolation_forest_waf.npz")
    export_random_forest(rf, rf_out)
    export_isolation_forest(iso, iso_out)
    prf, piso = PlainRandomForest(rf_out), PlainIsolationForest(iso_out)
    assert prf.feature_names == piso.feature_names == [str(n) for n in rf.feature_names_in_]

    rows = [[extract_features_from_request(url=u, method=m, body=b)[f] for f in prf.feature_names]
            for u, m, b in SAMPLES]
    rng = np.random.default_rng(0)
    rows += rng.integers(0, 60, size=(args.random_rows, len(prf.feature_names))).astype(float).tolist()
    rows += rng.random((args.random_rows, len(prf.feature_names))).tolist()
    worst = check(rf, iso, prf, piso, rows)
    print(f"exported {rf_out} and {iso_out}; max |diff| vs sklearn over {len(rows)} rows = {worst:.3e}")
    assert worst < 1e-9, worst


if __name__ == "__main__":
    main()
