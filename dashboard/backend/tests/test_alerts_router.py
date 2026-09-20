"""
Scenario: api/alerts.py had zero test coverage despite two real security-
relevant paths: (1) /recent's tenant filter (a non-admin must only ever see
their own alerts.get_all_alerts() rows, never another tenant's), and (2)
/connect/poll's ownership check (a pairing code is bound to the user_id that
requested it via /connect/start -- a different logged-in user polling with
that same code must be rejected, not silently linked to the wrong Telegram
chat). Also covers the [S4 FIX] pending-code cleanup (a second
/connect/start for the same user must invalidate their first code, not
leave two valid codes outstanding) and keeps every Telegram Bot API call
mocked (Ruling R3 -- no real network calls in tests).
"""
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import alerts as alerts_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(alerts_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_pending_codes():
    """alerts.py's _pending dict is module-level, process-wide state --
    without resetting it, one test's pairing code would leak into the next."""
    alerts_module._pending.clear()
    yield
    alerts_module._pending.clear()


# --------------------------------------------------------------- /recent

def test_non_admin_only_sees_their_own_alerts(client: TestClient, register_user, auth_header, monkeypatch):
    admin = register_user(email="alerts-admin@example.com", username="alerts_admin")
    viewer = register_user(email="alerts-viewer@example.com", username="alerts_viewer", role="viewer")

    all_alerts = [
        {"id": "a1", "user_id": admin["user"]["user_id"], "message": "admin's alert"},
        {"id": "a2", "user_id": viewer["user"]["user_id"], "message": "viewer's own alert"},
        {"id": "a3", "user_id": "some-other-user", "message": "a third tenant's alert"},
    ]
    monkeypatch.setattr(alerts_module.db, "get_all_alerts", MagicMock(return_value=all_alerts))

    resp = client.get("/api/alerts/recent", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    ids = {a["id"] for a in resp.json()["alerts"]}
    assert ids == {"a2"}, "a non-admin must only ever see their own alerts, never another tenant's"


def test_admin_sees_every_tenants_alerts(client: TestClient, register_user, auth_header, monkeypatch):
    admin = register_user(email="alerts-admin2@example.com", username="alerts_admin2")

    all_alerts = [
        {"id": "a1", "user_id": "user-x", "message": "x's alert"},
        {"id": "a2", "user_id": "user-y", "message": "y's alert"},
    ]
    monkeypatch.setattr(alerts_module.db, "get_all_alerts", MagicMock(return_value=all_alerts))

    resp = client.get("/api/alerts/recent", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
    ids = {a["id"] for a in resp.json()["alerts"]}
    assert ids == {"a1", "a2"}


# --------------------------------------------------------- connect/* flow

def test_second_connect_start_invalidates_the_first_code_for_the_same_user(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(alerts_module, "BOT_TOKEN", "fake-token-for-test")
    monkeypatch.setattr(alerts_module, "_get_bot_username", AsyncMock(return_value="testbot"))

    user = register_user(email="alerts-restart@example.com", username="alerts_restart")
    headers = auth_header(user["access_token"])

    first = client.post("/api/alerts/connect/start", headers=headers).json()
    second = client.post("/api/alerts/connect/start", headers=headers).json()

    assert first["code"] != second["code"] or True  # codes are random hex; collision is not what we're testing
    assert first["code"] not in alerts_module._pending, (
        "[S4 FIX] a second /connect/start for the same user must invalidate their first "
        "outstanding code, not leave two simultaneously valid"
    )
    assert second["code"] in alerts_module._pending


def test_connect_poll_rejects_a_code_that_belongs_to_a_different_user(
    client: TestClient, register_user, auth_header
):
    """Security-relevant: a pairing code is bound to the user_id that
    requested it. A different logged-in user polling with someone else's
    code must be rejected, not silently allowed to claim that Telegram
    chat link."""
    victim = register_user(email="alerts-victim@example.com", username="alerts_victim")
    attacker = register_user(email="alerts-attacker@example.com", username="alerts_attacker")

    alerts_module._pending["VICTIMCODE"] = {
        "user_id": victim["user"]["user_id"],
        "expires_at": time.time() + 300,
    }

    resp = client.get(
        "/api/alerts/connect/poll",
        params={"code": "VICTIMCODE"},
        headers=auth_header(attacker["access_token"]),
    )
    assert resp.status_code == 403


def test_connect_poll_rejects_an_expired_code(client: TestClient, register_user, auth_header):
    user = register_user(email="alerts-expired@example.com", username="alerts_expired")
    alerts_module._pending["EXPIRED1"] = {
        "user_id": user["user"]["user_id"],
        "expires_at": time.time() - 1,
    }

    resp = client.get(
        "/api/alerts/connect/poll",
        params={"code": "EXPIRED1"},
        headers=auth_header(user["access_token"]),
    )
    assert resp.status_code == 410
    assert "EXPIRED1" not in alerts_module._pending, "an expired code must be evicted once discovered, not left forever"


def test_connect_poll_rejects_an_unknown_code(client: TestClient, register_user, auth_header):
    user = register_user(email="alerts-unknown@example.com", username="alerts_unknown")
    resp = client.get(
        "/api/alerts/connect/poll",
        params={"code": "NOSUCHCODE"},
        headers=auth_header(user["access_token"]),
    )
    assert resp.status_code == 404


def test_connect_poll_success_path_saves_chat_id_and_invalidates_cache(
    client: TestClient, register_user, auth_header, monkeypatch
):
    user = register_user(email="alerts-success@example.com", username="alerts_success")
    user_id = user["user"]["user_id"]
    alerts_module._pending["GOODCODE"] = {"user_id": user_id, "expires_at": time.time() + 300}

    monkeypatch.setattr(alerts_module, "_check_telegram_for_code", AsyncMock(return_value=987654321))
    invalidate_spy = MagicMock()
    monkeypatch.setattr(alerts_module, "invalidate_user_cache", invalidate_spy)

    resp = client.get(
        "/api/alerts/connect/poll",
        params={"code": "GOODCODE"},
        headers=auth_header(user["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "connected", "chat_id": "987654321"}
    assert "GOODCODE" not in alerts_module._pending, "a consumed code must not be pollable/reusable again"
    assert invalidate_spy.call_count == 1

    status_resp = client.get("/api/alerts/connect/status", headers=auth_header(user["access_token"]))
    assert status_resp.json() == {"connected": True, "chat_id": "987654321"}


def test_connect_poll_still_waiting_when_telegram_has_not_seen_the_code_yet(
    client: TestClient, register_user, auth_header, monkeypatch
):
    user = register_user(email="alerts-waiting@example.com", username="alerts_waiting")
    alerts_module._pending["WAITCODE"] = {"user_id": user["user"]["user_id"], "expires_at": time.time() + 300}
    monkeypatch.setattr(alerts_module, "_check_telegram_for_code", AsyncMock(return_value=None))

    resp = client.get(
        "/api/alerts/connect/poll",
        params={"code": "WAITCODE"},
        headers=auth_header(user["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "waiting"}
    assert "WAITCODE" in alerts_module._pending, "an unconsumed code must remain pollable"


def test_disconnect_clears_chat_id_and_invalidates_cache(client: TestClient, register_user, auth_header, monkeypatch):
    user = register_user(email="alerts-disconnect@example.com", username="alerts_disconnect")
    user_id = user["user"]["user_id"]
    alerts_module.db.waf_users.update_item(
        Key={"user_id": user_id},
        UpdateExpression="SET telegram_chat_id = :c",
        ExpressionAttributeValues={":c": "111222333"},
    )
    invalidate_spy = MagicMock()
    monkeypatch.setattr(alerts_module, "invalidate_user_cache", invalidate_spy)

    resp = client.delete("/api/alerts/connect", headers=auth_header(user["access_token"]))
    assert resp.status_code == 200
    assert resp.json() == {"status": "disconnected"}
    assert invalidate_spy.call_count == 1

    status_resp = client.get("/api/alerts/connect/status", headers=auth_header(user["access_token"]))
    assert status_resp.json()["connected"] is False


# ------------------------------------------------- Telegram calls stay mocked

def test_check_telegram_for_code_never_makes_a_real_network_call(monkeypatch):
    """Ruling R3: no real network calls in tests. Confirms the httpx client
    used here is intercepted, not silently hitting api.telegram.org."""
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"result": []}

    client_cm = MagicMock()
    client_instance = MagicMock()
    client_instance.get = AsyncMock(return_value=fake_response)
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("api.alerts.httpx.AsyncClient", return_value=client_cm):
        import asyncio
        result = asyncio.run(alerts_module._check_telegram_for_code("ANYCODE"))

    assert result is None
    assert client_instance.get.call_count == 1
    called_url = client_instance.get.call_args[0][0]
    assert called_url.startswith("https://api.telegram.org/bot")
