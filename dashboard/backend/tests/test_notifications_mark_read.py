"""Real bug report (2026-09-22): clicking "Mark all read" in the dashboard
notification center did nothing -- notifications still showed as unread.

Root cause: POST /api/ai/notifications/mark-read only updates DynamoDB when
alert_id is given (`if alert_id: ...`). The frontend's "Mark all read"
button calls markRead(undefined) -- its own documented way of meaning
"all" (NotificationCenter.tsx's handleMarkAllRead) -- which posts
{"alert_id": null}. The endpoint then silently does nothing and still
returns {"success": True}, so the very next feed fetch shows the exact
same unread count."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import ai_summary as ai_summary_module
import services.dynamodb_service as dynamodb_service_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ai_summary_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_alerts_cache(fake_infrastructure):
    """The module-level _alerts_cache/_alerts_cache_ts globals in
    services/dynamodb_service.py are process-wide, not per-
    FakeDynamoDBService instance, and fake_infrastructure does not reset
    them. invalidate_alerts_cache() alone is NOT enough here: it only
    zeroes the TTL timestamp, but save_alert() unconditionally prepends
    onto the existing _alerts_cache list and stamps a fresh timestamp --
    so the very first seeded alert in a test makes the (still-stale-data)
    cache look "fresh" again, carrying every previous test's alerts along
    with it (confirmed empirically: a second test with 2 of its own seeds
    saw unread_count == 4, not 2). The list itself must be cleared too."""
    dynamodb_service_module.invalidate_alerts_cache()
    dynamodb_service_module._alerts_cache = []


def _seed_alert(alert_id: str):
    ai_summary_module.db.save_alert(
        user_id="u1", alert_id=alert_id, ip="1.2.3.4", url="/x",
        status="403", message="blocked",
    )


def test_mark_all_read_actually_marks_every_alert_read(client, register_user, auth_header):
    """The exact bug report, reproduced: click 'Mark all read' -> the
    frontend posts {"alert_id": null} -> unread_count must go to 0."""
    user = register_user(email="notif-user@example.com", username="notif_user")
    h = auth_header(user["access_token"])
    _seed_alert("alert-1")
    _seed_alert("alert-2")

    before = client.get("/api/ai/notifications/feed", headers=h).json()
    assert before["unread_count"] == 2

    resp = client.post("/api/ai/notifications/mark-read", json={}, headers=h)
    assert resp.status_code == 200, resp.text

    after = client.get("/api/ai/notifications/feed", headers=h).json()
    assert after["unread_count"] == 0


def test_mark_read_with_a_specific_alert_id_only_marks_that_one(client, register_user, auth_header):
    user = register_user(email="notif-user2@example.com", username="notif_user2")
    h = auth_header(user["access_token"])
    _seed_alert("alert-a")
    _seed_alert("alert-b")

    resp = client.post("/api/ai/notifications/mark-read", json={"alert_id": "alert-a"}, headers=h)
    assert resp.status_code == 200, resp.text

    after = client.get("/api/ai/notifications/feed", headers=h).json()
    assert after["unread_count"] == 1
    unread_ids = [n["alert_id"] for n in after["notifications"] if not n["read"]]
    assert unread_ids == ["alert-b"]


def test_mark_all_read_with_zero_alerts_does_not_error(client, register_user, auth_header):
    user = register_user(email="notif-user3@example.com", username="notif_user3")
    h = auth_header(user["access_token"])

    resp = client.post("/api/ai/notifications/mark-read", json={}, headers=h)
    assert resp.status_code == 200, resp.text


def test_mark_read_uses_the_real_composite_key_schema(client, register_user, auth_header, monkeypatch):
    """The deeper real bug: the key schema is composite, not a plain
    alert_id key, and a Key that does not match it raises
    ValidationException -- which this handler's blanket except turns into
    a 500. This locks in the exact Key shape passed to update_item, which
    a behavioural pass/fail on the fake in-memory table alone cannot
    distinguish (it matches on whatever subset of fields is given, unlike
    real DynamoDB).

    Updated 2026-09-23 for the migration to waf_alerts_v2: the partition
    key is now origin_id (the origin the alert belongs to) instead of
    user_id, which was the constant "default-user" and identified
    nothing."""
    from unittest.mock import MagicMock

    user = register_user(email="notif-user4@example.com", username="notif_user4")
    h = auth_header(user["access_token"])
    _seed_alert("alert-composite")

    update_spy = MagicMock()
    monkeypatch.setattr(ai_summary_module.db.alerts_table, "update_item", update_spy)

    resp = client.post("/api/ai/notifications/mark-read", json={"alert_id": "alert-composite"}, headers=h)
    assert resp.status_code == 200, resp.text

    assert update_spy.call_count == 1
    key_used = update_spy.call_args.kwargs["Key"]
    assert key_used == {"origin_id": "unattributed", "alert_id": "alert-composite"}
