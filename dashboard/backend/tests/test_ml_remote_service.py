"""The ML service can run on a separate host (deploy/azure-ml): api/ml.py reads
its address, token and timeout from the environment, sends the token on every
call, and can be told not to forward lab capture at all. With nothing set the
behaviour must stay exactly as before (local service, no token header)."""
import os
import types
from typing import ClassVar

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import ml
from services.rbac import require_viewer_or_above


class _FakeResponse:
    status_code = 200
    headers: ClassVar[dict] = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class _RecordingAsyncClient:
    """Stand-in for httpx.AsyncClient that records every outbound call."""

    calls: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, content=None, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": dict(headers or {}), "timeout": timeout})
        return _FakeResponse({"is_anomaly": False, "attack_probability": 0.1})


@pytest.fixture
def outbound(monkeypatch):
    _RecordingAsyncClient.calls = []
    monkeypatch.setattr(ml, "httpx", types.SimpleNamespace(
        AsyncClient=_RecordingAsyncClient,
        RequestError=httpx.RequestError,
        HTTPStatusError=httpx.HTTPStatusError,
    ))
    monkeypatch.setattr(ml, "_is_internal_relay_request", lambda request: True)

    async def no_explanation(request_context, attribution):
        return "n/a"

    monkeypatch.setattr(ml.gemini_service, "explain_attribution", no_explanation)
    app = FastAPI()
    app.include_router(ml.router)
    app.dependency_overrides[require_viewer_or_above] = lambda: {"user_id": "u-1", "role": "viewer"}
    return TestClient(app), _RecordingAsyncClient.calls


def _remote(monkeypatch, token="t0ken", capture_url=None):
    monkeypatch.setattr(ml, "ML_SERVICE_URL", "http://10.77.0.2:5000")
    monkeypatch.setattr(ml, "ML_SERVICE_TOKEN", token)
    monkeypatch.setattr(ml, "ML_FAST_TIMEOUT", 0.9)
    monkeypatch.setattr(ml, "ML_CAPTURE_URL", "http://10.77.0.2:5000" if capture_url is None else capture_url)


def test_defaults_are_the_local_service_without_token():
    if "ML_SERVICE_URL" not in os.environ:
        assert ml.ML_SERVICE_URL == "http://127.0.0.1:5000"
    if "ML_SERVICE_TOKEN" not in os.environ:
        assert ml._ml_headers() == {}
    if "ML_FAST_TIMEOUT" not in os.environ:
        assert ml.ML_FAST_TIMEOUT == 0.5


def test_no_token_header_when_token_unset(outbound, monkeypatch):
    client, calls = outbound
    monkeypatch.setattr(ml, "ML_SERVICE_TOKEN", "")
    client.get("/api/ml/shadow/decision", headers={"X-Original-URI": "/a"})
    assert calls and ml.ML_TOKEN_HEADER not in calls[0]["headers"]


def test_shadow_relay_uses_remote_url_token_and_timeout(outbound, monkeypatch):
    client, calls = outbound
    _remote(monkeypatch)
    resp = client.get("/api/ml/shadow/decision", headers={"X-Original-URI": "/a?id=1"})
    assert resp.status_code == 204
    assert calls[0]["url"] == "http://10.77.0.2:5000/predict-fast"
    assert calls[0]["headers"][ml.ML_TOKEN_HEADER] == "t0ken"
    assert calls[0]["timeout"] == 0.9


def test_predict_and_rule_generation_send_the_token(outbound, monkeypatch):
    client, calls = outbound
    _remote(monkeypatch)
    assert client.post("/api/ml/predict", json={"url": "/"}).status_code == 200
    assert calls[-1]["url"] == "http://10.77.0.2:5000/predict"
    assert all(c["headers"].get(ml.ML_TOKEN_HEADER) == "t0ken" for c in calls)


def test_capture_is_not_forwarded_when_capture_url_is_empty(outbound, monkeypatch):
    client, calls = outbound
    _remote(monkeypatch, capture_url="")
    resp = client.post("/api/ml/capture", content=b"a=1", headers={"X-Original-URI": "/x"})
    assert resp.status_code == 204
    assert calls == []


def test_capture_goes_to_capture_url_with_token(outbound, monkeypatch):
    client, calls = outbound
    _remote(monkeypatch, capture_url="http://10.77.0.9:5000")
    client.post("/api/ml/capture", content=b"a=1", headers={"X-Original-URI": "/x"})
    assert calls[0]["url"] == "http://10.77.0.9:5000/capture"
    assert calls[0]["headers"][ml.ML_TOKEN_HEADER] == "t0ken"
    assert calls[0]["headers"]["X-Original-URI"] == "/x"


@pytest.mark.parametrize("raw, expected", [("1.5", 1.5), ("", 0.5), ("abc", 0.5), ("0", 0.5), ("-2", 0.5)])
def test_bad_timeout_value_keeps_the_default(monkeypatch, raw, expected):
    monkeypatch.setenv("ML_FAST_TIMEOUT_TEST", raw)
    assert ml._env_float("ML_FAST_TIMEOUT_TEST", 0.5) == expected
