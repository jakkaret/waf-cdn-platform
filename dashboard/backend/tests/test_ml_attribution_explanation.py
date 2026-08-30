"""
Scenario: T10 - turn the model's per-feature attribution (T9) into a Thai
explanation, surfaced by both /api/ml/predict and /api/ml/predict-and-suggest.

Ruling R2 (task-10-brief.md): the explanation is generated in the dashboard
backend by extending GeminiService with a new method (explain_attribution)
that mirrors explain_attack's existing cache/httpx/fallback shape.
httpx.AsyncClient (a single process-wide object shared by
services.gemini_service and api.ml -- see the fakes section below) is
monkeypatched so no test ever calls the real Gemini API or the real ML
service.

This module defines its own `app`/`client` fixtures, overriding conftest.py's
for this file only (pytest fixture resolution: a fixture defined in the test
module wins over one from conftest for tests in that module) -- the shared
minimal app in conftest.py deliberately does not include api.ml's router
(see its docstring), and every other fixture (fake_infrastructure,
register_user, auth_header, ...) is reused unchanged from conftest.py so
auth/RBAC stay real, per the brief's instruction not to weaken that
guarantee.
"""
import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from services.gemini_service import GeminiService, FEATURE_LABELS_TH
from services.gemini_service import gemini_service as gemini_service_singleton
from api import auth as auth_module
from api import ml as ml_module

# ml/feature_engineering.py lives at the repo root, not under
# dashboard/backend (which conftest.py already put on sys.path) -- add the
# repo root too, just for this module, so FEATURE_COLUMNS can be imported
# from its single source of truth instead of duplicating the list here.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.feature_engineering import FEATURE_COLUMNS  # noqa: E402


# Real live values observed for `?id=1' UNION SELECT 1,2,3--` per the T9
# contract quoted in this task's brief.
ATTRIBUTION = [
    {"feature": "keyword_matches", "value": 1.0, "contribution": 0.2289},
    {"feature": "special_char_ratio", "value": 0.0357, "contribution": 0.1034},
    {"feature": "quote_unbalanced", "value": 1.0, "contribution": 0.0839},
]


# ---------------------------------------------------------------------------
# Fakes for httpx.AsyncClient.
#
# services/gemini_service.py and api/ml.py both do a plain `import httpx`,
# so the `httpx` name in each module's namespace refers to the exact same
# module object -- there is exactly one `httpx.AsyncClient` attribute in the
# whole process, not one per importer. Patching it twice with two unrelated
# factories (one "for Gemini", one "for the ML service") would just have the
# second patch silently clobber the first. So there is one patch point
# (`_patch_httpx`) and one fake client that dispatches by the request URL:
# Gemini's BASE_URL contains "generativelanguage.googleapis.com"; the ML
# service's is "http://127.0.0.1:5000/...".
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class _RoutingFakeAsyncClient:
    """Stands in for httpx.AsyncClient as an async context manager; routes
    .post(url, ...) to a canned Gemini or ML-service response by URL."""

    def __init__(self, gemini_response=None, gemini_raise=None, ml_response=None, calls=None, **_kwargs):
        self._gemini_response = gemini_response
        self._gemini_raise = gemini_raise
        self._ml_response = ml_response
        self._calls = calls if calls is not None else {"gemini": [], "ml": []}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, *args, **kwargs):
        if "generativelanguage.googleapis.com" in url:
            self._calls["gemini"].append((url, kwargs))
            if self._gemini_raise is not None:
                raise self._gemini_raise
            return self._gemini_response
        self._calls["ml"].append((url, kwargs))
        return self._ml_response


def _patch_httpx(monkeypatch, gemini_response=None, gemini_raise=None, ml_response=None):
    """Patch the one, process-wide httpx.AsyncClient. Returns a dict of call
    lists: {"gemini": [...], "ml": [...]}."""
    calls = {"gemini": [], "ml": []}

    def _factory(*_args, **_kwargs):
        return _RoutingFakeAsyncClient(
            gemini_response=gemini_response, gemini_raise=gemini_raise,
            ml_response=ml_response, calls=calls,
        )

    # Either module reference works -- they are the same object -- patching
    # through ml_module here for symmetry with the endpoint tests below.
    monkeypatch.setattr(ml_module.httpx, "AsyncClient", _factory)
    return calls


def _gemini_ok_response(text="คำอธิบายจาก Gemini"):
    return _FakeResponse(200, json_data={"candidates": [{"content": {"parts": [{"text": text}]}}]})


@pytest.fixture(autouse=True)
def _reset_gemini_singleton_cache():
    """api/ml.py calls the module-level `gemini_service` singleton, which
    lives for the whole test process. Clear its caches before and after
    every test in this module so one test's cached explanation can never
    leak into another's assertions (independent of the sibling suite's own
    fake_infrastructure fixture, which this does not touch or weaken)."""
    gemini_service_singleton._attribution_cache.clear()
    gemini_service_singleton._attack_cache.clear()
    yield
    gemini_service_singleton._attribution_cache.clear()
    gemini_service_singleton._attack_cache.clear()


# ---------------------------------------------------------------------------
# GeminiService.explain_attribution: fallback behaviour
# ---------------------------------------------------------------------------

def test_fallback_on_gemini_exception(monkeypatch):
    """With the HTTP call patched to raise, a non-empty Thai string is still
    returned and names the top contributing feature."""
    _patch_httpx(monkeypatch, gemini_raise=RuntimeError("network down"))
    svc = GeminiService()

    explanation = asyncio.run(
        svc.explain_attribution({"url": "/vuln?id=1", "method": "GET"}, ATTRIBUTION)
    )

    assert explanation
    assert isinstance(explanation, str)
    assert FEATURE_LABELS_TH["keyword_matches"] in explanation


def test_fallback_on_non_200(monkeypatch):
    """Same, for a 500 from the Gemini API."""
    _patch_httpx(monkeypatch, gemini_response=_FakeResponse(500, text="server error"))
    svc = GeminiService()

    explanation = asyncio.run(
        svc.explain_attribution({"url": "/vuln?id=1", "method": "GET"}, ATTRIBUTION)
    )

    assert explanation
    assert FEATURE_LABELS_TH["keyword_matches"] in explanation


def test_never_raises_on_malformed_contribution_value(monkeypatch):
    """Acceptance criterion 2 says 'never raise', full stop -- not just
    'never raise once the HTTP call has started'. A non-numeric
    `contribution` (which T9's contract should never produce, but this
    method must not trust blindly) must still degrade to the fallback
    instead of letting a ValueError/TypeError from float() escape."""
    _patch_httpx(monkeypatch, gemini_response=_gemini_ok_response())
    svc = GeminiService()
    malformed = [
        {"feature": "keyword_matches", "value": 1.0, "contribution": "not-a-number"},
        {"feature": "special_char_ratio", "value": 0.03, "contribution": None},
    ]

    explanation = asyncio.run(
        svc.explain_attribution({"url": "/vuln?id=1", "method": "GET"}, malformed)
    )

    assert explanation
    assert isinstance(explanation, str)


def test_fallback_never_raises_even_with_no_attribution(monkeypatch):
    """Sanity check for the "missing attribution" case at the service layer:
    no HTTP call is even attempted when there is nothing to explain."""
    calls = _patch_httpx(monkeypatch, gemini_raise=AssertionError("must not be called"))
    svc = GeminiService()

    explanation = asyncio.run(svc.explain_attribution({"url": "/x", "method": "GET"}, None))

    assert explanation
    assert isinstance(explanation, str)
    assert calls["gemini"] == []


# ---------------------------------------------------------------------------
# Feature labels
# ---------------------------------------------------------------------------

def test_every_feature_column_has_a_distinct_non_empty_thai_label():
    assert set(FEATURE_LABELS_TH.keys()) == set(FEATURE_COLUMNS)
    labels = list(FEATURE_LABELS_TH.values())
    assert all(isinstance(label, str) and label.strip() for label in labels)
    assert len(set(labels)) == len(labels)  # all 13 labels are distinct


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_two_calls_same_signature_make_one_http_call(monkeypatch):
    calls = _patch_httpx(monkeypatch, gemini_response=_gemini_ok_response())
    svc = GeminiService()
    context = {"url": "/vuln?id=1", "method": "GET"}

    first = asyncio.run(svc.explain_attribution(context, ATTRIBUTION))
    second = asyncio.run(svc.explain_attribution(context, ATTRIBUTION))

    assert first == second == "คำอธิบายจาก Gemini"
    assert len(calls["gemini"]) == 1


# ---------------------------------------------------------------------------
# Endpoint wiring: predict / predict-and-suggest
#
# Local `app`/`client` fixtures (see module docstring) add api.ml's router,
# which conftest.py's shared minimal app does not include.
# ---------------------------------------------------------------------------

@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ml_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_predict_includes_explanation_and_handles_missing_attribution(
    client: TestClient, register_user, auth_header, monkeypatch
):
    """When the ML service response has no `attribution` (T9 says this is a
    normal case -- e.g. an older ML service during rollout), /predict still
    returns 200 with a non-empty `explanation`, and no Gemini HTTP call is
    even attempted."""
    calls = _patch_httpx(
        monkeypatch,
        gemini_raise=AssertionError("must not be called"),
        ml_response=_FakeResponse(200, json_data={"is_anomaly": False, "score": 0.1}),
    )

    user = register_user(email="ml-user@example.com", username="ml_user")
    resp = client.post(
        "/api/ml/predict",
        json={"url": "/test?x=1", "method": "GET", "body": ""},
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "explanation" in body
    assert isinstance(body["explanation"], str) and body["explanation"]
    assert calls["gemini"] == []


def test_predict_includes_explanation_when_attribution_present(
    client: TestClient, register_user, auth_header, monkeypatch
):
    _patch_httpx(
        monkeypatch,
        gemini_response=_gemini_ok_response("อธิบายว่าทำไมโดนบล็อก"),
        ml_response=_FakeResponse(200, json_data={
            "is_anomaly": True,
            "score": 0.9,
            "attribution": ATTRIBUTION,
            "attribution_baseline": 0.5001,
        }),
    )

    user = register_user(email="ml-user2@example.com", username="ml_user2")
    resp = client.post(
        "/api/ml/predict",
        json={"url": "/vuln?id=1' UNION SELECT 1,2,3--", "method": "GET", "body": ""},
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["explanation"] == "อธิบายว่าทำไมโดนบล็อก"
    assert body["attribution"] == ATTRIBUTION  # existing field untouched


def test_predict_and_suggest_returns_prediction_and_suggested_rule_keys(
    client: TestClient, register_user, auth_header, monkeypatch
):
    """`predict-and-suggest` must still return {"prediction": ..., "suggested_rule": ...}."""
    _patch_httpx(
        monkeypatch,
        gemini_response=_gemini_ok_response("อธิบายผลการวิเคราะห์"),
        ml_response=_FakeResponse(200, json_data={
            "is_anomaly": False,  # avoids MLRuleService/DynamoDB entirely; out of this task's scope
            "score": 0.2,
            "attribution": ATTRIBUTION,
            "attribution_baseline": 0.5001,
        }),
    )

    user = register_user(email="ml-user3@example.com", username="ml_user3")
    resp = client.post(
        "/api/ml/predict-and-suggest",
        json={"url": "/vuln?id=1", "method": "GET", "body": ""},
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body.keys()) == {"prediction", "suggested_rule"}
    assert body["suggested_rule"] is None
    assert body["prediction"]["explanation"] == "อธิบายผลการวิเคราะห์"
    assert body["prediction"]["is_anomaly"] is False


# ---------------------------------------------------------------------------
# No execution sink
# ---------------------------------------------------------------------------

def test_explanation_never_reaches_an_execution_sink_or_rule_generation():
    """Assert by construction (static inspection of the code under test,
    per the brief) that the explanation string:
      1. never touches a SQL/shell/file-write/eval sink anywhere in either
         file, because no such sink exists in either file at all, and
      2. is never referenced inside the pending-rule-generation block, which
         builds the payload sent to MLRuleService.create_pending_rule() and
         becomes a live ModSecurity rule.

    See the report for how this was additionally verified by reading the
    code: `_attach_explanation` in api/ml.py only ever does
    `result["explanation"] = ...` and returns `result`; the rule-generation
    block below it builds `rule_data` solely from `rule_res.json()` (the ML
    service's own /generate-rule response) and `req.url/method/body`, never
    from `result` or `explanation`. `explain_attribution` in
    gemini_service.py only builds a prompt string, calls httpx, and returns
    text -- it contains no subprocess/SQL/file-write call either.
    """
    backend_dir = Path(__file__).resolve().parent.parent
    ml_src = (backend_dir / "api" / "ml.py").read_text(encoding="utf-8")
    gemini_src = (backend_dir / "services" / "gemini_service.py").read_text(encoding="utf-8")

    forbidden_sinks = (
        "subprocess", "os.system", "os.popen", "os.exec",
        ".execute(", "eval(", "open(",
    )
    for sink in forbidden_sinks:
        assert sink not in ml_src, f"forbidden sink {sink!r} found in api/ml.py"
        assert sink not in gemini_src, f"forbidden sink {sink!r} found in services/gemini_service.py"

    # The rule-generation block (from the /generate-rule call through the
    # create_pending_rule() call) never mentions "explanation".
    start = ml_src.index('f"{ML_SERVICE_URL}/generate-rule"')
    end = ml_src.index("return {", start)
    rule_generation_block = ml_src[start:end]
    assert "explanation" not in rule_generation_block
