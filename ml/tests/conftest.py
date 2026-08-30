"""Minimal, standalone fixtures for the `ml/tests/` suite.

This suite is independent from `dashboard/backend/tests/` (a different
project, a different conftest, different needs) -- it does not import from
or extend that suite's conftest.

Skips cleanly (rather than failing) when scikit-learn or the model artifact
is unavailable, so the suite never fails just for running on the wrong
machine.
"""
import os
import sys

import pytest

# Ensure the repo root is on sys.path so `ml.*` imports resolve the same
# way whether pytest is invoked as `python -m pytest ml/tests/` from the
# repo root (the documented invocation) or from elsewhere.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

sklearn = pytest.importorskip("sklearn", reason="scikit-learn not installed")

MODEL_PATH = os.path.join(REPO_ROOT, "ml", "models", "random_forest_waf.joblib")


@pytest.fixture(scope="session")
def rf_model():
    """The production RandomForest, loaded directly with joblib -- not via
    ml_api's `@app.on_event("startup")` handler, so this stays fast and
    independent of the FastAPI app lifecycle."""
    if not os.path.exists(MODEL_PATH):
        pytest.skip(f"model artifact not found: {MODEL_PATH}")
    import joblib

    # joblib.load executes a pickle. This is safe here: the artifact is
    # committed to this repo (not fetched from an untrusted source) and is
    # the same file production loads via ml_api.py's own joblib.load call.
    return joblib.load(MODEL_PATH)
