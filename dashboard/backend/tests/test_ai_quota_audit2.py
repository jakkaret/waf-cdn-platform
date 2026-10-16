"""Re-audit 2026-10-17: Gemini-backed copilot chat and summarize-range are
capped per user and their inputs are length-bounded."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import services.ai_quota as ai_quota
from api import auth as auth_module, copilot as copilot_module, ai_summary as ai_module
from services.rate_limiter import limiter


class _CountingLimiter:
    """Same interface as RedisRateLimiter.is_allowed (fakeredis has no Lua)."""
    def __init__(self):
        self.n = {}

    def is_allowed(self, key, limit, window_seconds, fail_open=True):
        assert fail_open is False
        self.n[key] = self.n.get(key, 0) + 1
        return self.n[key] <= limit, max(0, limit - self.n[key]), 60


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(ai_quota, "AI_CALLS_PER_HOUR", 3)
    monkeypatch.setattr(ai_quota, "_limiter", _CountingLimiter())
    calls = []

    async def fake_post(self, url, *a, **kw):
        import httpx
        calls.append(url)
        return httpx.Response(500, request=httpx.Request("POST", url))

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    a = FastAPI()
    a.state.limiter = limiter
    for m in (auth_module, copilot_module, ai_module):
        a.include_router(m.router)
    c = TestClient(a)
    c.calls = calls
    return c


def _h(register_user, email):
    u = register_user(email=email, username=email.split("@")[0])
    return {"Authorization": f"Bearer {u['access_token']}"}


def test_copilot_capped_per_user(client, register_user):
    h = _h(register_user, "q1@example.com")
    codes = [client.post("/api/copilot/chat", json={"message": "hi"}, headers=h).status_code for _ in range(4)]
    assert 429 not in codes[:3]
    assert codes[3] == 429


def test_quota_is_per_user(client, register_user):
    h1 = _h(register_user, "q2@example.com")
    h2 = _h(register_user, "q3@example.com")
    for _ in range(3):
        client.post("/api/copilot/chat", json={"message": "hi"}, headers=h1)
    assert client.post("/api/copilot/chat", json={"message": "hi"}, headers=h1).status_code == 429
    assert client.post("/api/copilot/chat", json={"message": "hi"}, headers=h2).status_code != 429


def test_summarize_range_shares_the_cap(client, register_user):
    h = _h(register_user, "q4@example.com")
    for _ in range(3):
        client.post("/api/copilot/chat", json={"message": "hi"}, headers=h)
    r = client.post("/api/ai/summarize-range", json={"query": "last hour"}, headers=h)
    assert r.status_code == 429


def test_history_and_content_bounded(client, register_user):
    h = _h(register_user, "q5@example.com")
    big = [{"role": "user", "content": "x" * 4001}]
    assert client.post("/api/copilot/chat", json={"message": "hi", "history": big}, headers=h).status_code == 422
    many = [{"role": "user", "content": "x"}] * 21
    assert client.post("/api/copilot/chat", json={"message": "hi", "history": many}, headers=h).status_code == 422
    assert client.post("/api/ai/summarize-range", json={"query": "x" * 501}, headers=h).status_code == 422


def test_quota_fails_closed_when_redis_errors(client, register_user, monkeypatch):
    from services.rate_limiter import RedisRateLimiter
    lim = RedisRateLimiter()
    monkeypatch.setattr(lim, "script_runner", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr(ai_quota, "_limiter", lim)
    h = _h(register_user, "q6@example.com")
    assert client.post("/api/copilot/chat", json={"message": "hi"}, headers=h).status_code == 429
