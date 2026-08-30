"""Tests for `ml/attribution.py` (task T9).

TDD: written against the module's intended shape before the implementation
existed. Run with:

    ./dashboard/backend/.venv/bin/python -m pytest ml/tests/ -v

No network calls. Skips cleanly (via the `rf_model` fixture and the
`sklearn` importorskip in conftest.py) when scikit-learn or the model
artifact is unavailable.
"""
import pandas as pd
import pytest

from ml.attribution import build_attribution_response, compute_forest_attribution
from ml.feature_engineering import FEATURE_COLUMNS, extract_features_from_request

# The five varied inputs the brief asks for: benign, SQLi, XSS, traversal, empty.
SAMPLE_REQUESTS = {
    "benign": dict(url="/index.html", method="GET", body=""),
    "sqli": dict(url="/?id=1' UNION SELECT 1,2,3--", method="GET", body=""),
    "xss": dict(url="/?q=<script>alert(1)</script>", method="GET", body=""),
    "traversal": dict(url="/../../etc/passwd", method="GET", body=""),
    "empty": dict(url="", method="GET", body=""),
}


def _feature_row(**request_kwargs) -> pd.DataFrame:
    """Build the single-row DataFrame ml_api.py itself builds for /predict."""
    features = extract_features_from_request(**request_kwargs)
    return pd.DataFrame([features])[FEATURE_COLUMNS]


# ---------------------------------------------------------------------------
# additivity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(SAMPLE_REQUESTS.keys()))
def test_additivity(rf_model, name):
    """bias + sum(contributions) == rf.predict_proba(x)[0][1], within 1e-9,
    for every one of the five varied inputs."""
    df_feat = _feature_row(**SAMPLE_REQUESTS[name])

    bias, contributions = compute_forest_attribution(rf_model, df_feat)
    reconstructed = bias + sum(contributions.values())

    expected = rf_model.predict_proba(df_feat)[0][1]

    assert reconstructed == pytest.approx(expected, abs=1e-9)


# ---------------------------------------------------------------------------
# completeness
# ---------------------------------------------------------------------------

def test_completeness(rf_model):
    """Exactly 13 entries, names equal to FEATURE_COLUMNS as a set."""
    assert len(FEATURE_COLUMNS) == 13

    df_feat = _feature_row(**SAMPLE_REQUESTS["sqli"])
    _, contributions = compute_forest_attribution(rf_model, df_feat)

    assert len(contributions) == 13
    assert set(contributions.keys()) == set(FEATURE_COLUMNS)

    # Same guarantee at the API response layer.
    response = build_attribution_response(rf_model, df_feat)
    assert len(response["attribution"]) == 13
    assert {entry["feature"] for entry in response["attribution"]} == set(FEATURE_COLUMNS)


# ---------------------------------------------------------------------------
# ordering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", list(SAMPLE_REQUESTS.keys()))
def test_ordering(rf_model, name):
    """attribution is sorted by |contribution| descending."""
    df_feat = _feature_row(**SAMPLE_REQUESTS[name])
    response = build_attribution_response(rf_model, df_feat)

    magnitudes = [abs(entry["contribution"]) for entry in response["attribution"]]
    assert magnitudes == sorted(magnitudes, reverse=True)


# ---------------------------------------------------------------------------
# direction
# ---------------------------------------------------------------------------

def test_direction_sqli_keyword_matches_top_positive(rf_model):
    """For the SQLi payload, keyword_matches is the top contributor and its
    contribution is positive -- the model's global importance for it is
    31.3%, so anything else indicates a wiring error."""
    df_feat = _feature_row(**SAMPLE_REQUESTS["sqli"])
    response = build_attribution_response(rf_model, df_feat)

    top = response["attribution"][0]
    assert top["feature"] == "keyword_matches"
    assert top["contribution"] > 0


# ---------------------------------------------------------------------------
# benign contrast
# ---------------------------------------------------------------------------

def test_benign_contrast_lower_total_than_sqli(rf_model):
    """For a plainly benign request the summed contribution is lower than
    for the SQLi case."""
    benign_df = _feature_row(**SAMPLE_REQUESTS["benign"])
    sqli_df = _feature_row(**SAMPLE_REQUESTS["sqli"])

    _, benign_contrib = compute_forest_attribution(rf_model, benign_df)
    _, sqli_contrib = compute_forest_attribution(rf_model, sqli_df)

    assert sum(benign_contrib.values()) < sum(sqli_contrib.values())


# ---------------------------------------------------------------------------
# degradation
# ---------------------------------------------------------------------------

def test_degradation_predict_survives_attribution_failure(rf_model, monkeypatch):
    """When attribution raises, /predict still returns the original fields
    (is_anomaly, attack_probability, anomaly_score, status, confidence,
    features) and simply omits attribution -- detection must never go down
    because an explanation could not be produced.

    The failure is simulated by monkeypatching the attribution builder, not
    by breaking the model.
    """
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    TestClient = fastapi_testclient.TestClient

    import ml.ml_api as ml_api_module

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated attribution failure")

    monkeypatch.setattr(ml_api_module, "build_attribution_response", _boom)

    with TestClient(ml_api_module.app) as client:
        resp = client.post(
            "/predict",
            json={"url": "/index.html", "method": "GET", "body": ""},
        )

    assert resp.status_code == 200
    data = resp.json()

    for key in (
        "is_anomaly",
        "attack_probability",
        "anomaly_score",
        "status",
        "confidence",
        "features",
    ):
        assert key in data

    assert "attribution" not in data
    assert "attribution_baseline" not in data
