"""F-113 regression: POST /api/ml/predict-and-suggest is capped per user so a
viewer cannot flood the admin approval queue (or the Gemini budget)."""
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api import ml
from services.rbac import require_viewer_or_above


class _CountingLimiter:
    """Same interface as services.rate_limiter.RedisRateLimiter.is_allowed;
    fakeredis cannot run that class's Lua script without the optional lupa
    package, so the endpoint wiring is tested against this stand-in."""

    def __init__(self):
        self.counts = {}

    def is_allowed(self, key, limit, window_seconds):
        n = self.counts.get(key, 0)
        if n >= limit:
            return False, n, window_seconds
        self.counts[key] = n + 1
        return True, n + 1, 0


@pytest.fixture(autouse=True)
def fresh_limiter(monkeypatch):
    monkeypatch.setattr(ml, "_suggest_limiter", _CountingLimiter())
    monkeypatch.setattr(ml, "SUGGEST_LIMIT_PER_HOUR", 3)


def test_quota_allows_up_to_the_limit_then_429():
    for _ in range(3):
        ml._check_suggest_quota("u-a")
    with pytest.raises(HTTPException) as e:
        ml._check_suggest_quota("u-a")
    assert e.value.status_code == 429
    assert int(e.value.headers["Retry-After"]) >= 1


def test_quota_is_per_user():
    for _ in range(3):
        ml._check_suggest_quota("u-a")
    ml._check_suggest_quota("u-b")  # another user is unaffected


def test_endpoint_rejects_before_calling_the_ml_service(monkeypatch):
    app = FastAPI()
    app.include_router(ml.router)
    app.dependency_overrides[require_viewer_or_above] = lambda: {"user_id": "u-c", "role": "viewer"}
    # Unreachable ML service: an allowed call fails with 503, a capped one with 429.
    monkeypatch.setattr(ml, "ML_SERVICE_URL", "http://127.0.0.1:1")
    client = TestClient(app)
    body = {"url": "/", "method": "GET", "body": ""}
    codes = [client.post("/api/ml/predict-and-suggest", json=body).status_code for _ in range(4)]
    assert codes[:3] == [503, 503, 503]
    assert codes[3] == 429
