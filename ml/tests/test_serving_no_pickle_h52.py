"""H52: /predict serves the forests from pickle-free .npz files and still
returns exactly what the joblib/sklearn version returned in production."""
import json
import math
import os
import subprocess
import sys

import numpy as np
import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS = os.path.join(REPO, "ml", "models")
GOLDEN = os.path.join(os.path.dirname(__file__), "data", "predict_golden_2026-10-16.json")


def _close(a, b, path=""):
    if isinstance(a, dict):
        assert set(a) == set(b), path
        for k in a:
            _close(a[k], b[k], f"{path}.{k}")
    elif isinstance(a, list):
        assert len(a) == len(b), path
        for i, (x, y) in enumerate(zip(a, b)):
            _close(x, y, f"{path}[{i}]")
    elif isinstance(a, float) or isinstance(b, float):
        assert math.isclose(a, b, abs_tol=1.5e-4), f"{path}: {a} != {b}"
    else:
        assert a == b, f"{path}: {a!r} != {b!r}"


def test_npz_files_load_without_pickle():
    for name in ("random_forest_waf.npz", "isolation_forest_waf.npz"):
        with np.load(os.path.join(MODELS, name), allow_pickle=False) as z:
            assert all(z[k].dtype != object for k in z.files), name


def test_serving_imports_neither_joblib_nor_sklearn():
    code = "import sys, ml.ml_api; print('joblib' in sys.modules, 'sklearn' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env={**os.environ, "PYTHONPATH": REPO},
                         capture_output=True, text=True, check=True).stdout.split()
    assert out == ["False", "False"]


def test_no_joblib_load_in_runtime_modules():
    for mod in ("ml_api.py", "plain_forest.py", "attribution.py", "onnx_inference.py",
                "feature_engineering.py", "gen3_onnx.py", "async_log_analyzer.py"):
        text = open(os.path.join(REPO, "ml", mod), encoding="utf-8").read()
        assert "joblib.load" not in text and "pickle.load" not in text, mod


def test_predict_matches_production_golden():
    from fastapi.testclient import TestClient
    import ml.ml_api as api

    golden = json.load(open(GOLDEN, encoding="utf-8"))
    with TestClient(api.app) as client:
        health = client.get("/health").json()
        assert sorted(health) == golden["health_keys"]
        assert sorted(health["models_loaded"]) == golden["models_loaded_keys"]
        assert health["models_loaded"] == {"random_forest": True, "isolation_forest": True}
        for case in golden["predict"]:
            url, method, body = case["req"]
            got = client.post("/predict", json={"url": url, "method": method, "body": body}).json()
            _close(got, case["resp"], url[:40])


def test_plain_forest_matches_sklearn_exactly():
    joblib = pytest.importorskip("joblib")
    pd = pytest.importorskip("pandas")
    from ml.attribution import compute_forest_attribution
    from ml.plain_forest import PlainIsolationForest, PlainRandomForest

    # Test-only unpickle of the committed training artifacts, to compare.
    rf = joblib.load(os.path.join(MODELS, "random_forest_waf.joblib"))
    iso = joblib.load(os.path.join(MODELS, "isolation_forest_waf.joblib"))
    prf = PlainRandomForest(os.path.join(MODELS, "random_forest_waf.npz"))
    piso = PlainIsolationForest(os.path.join(MODELS, "isolation_forest_waf.npz"))
    rng = np.random.default_rng(7)
    rows = rng.integers(0, 40, size=(200, len(prf.feature_names))).astype(float).tolist()
    for values in rows:
        df = pd.DataFrame([values], columns=prf.feature_names)
        p, bias, contrib = prf.explain(values)
        sk_bias, sk_contrib = compute_forest_attribution(rf, df)
        assert abs(p - rf.predict_proba(df)[0][1]) < 1e-12
        assert prf.predict(values) == rf.predict(df)[0]
        assert abs(bias - sk_bias) < 1e-12
        assert max(abs(contrib[f] - sk_contrib[f]) for f in contrib) < 1e-12
        assert abs(piso.decision_function(values) - iso.decision_function(df)[0]) < 1e-12
