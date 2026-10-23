"""Telegram alerts go only to users allowed to see the alert (KNOWN_ISSUES #8):
the origin's team, and platform admins only for unattributed alerts or an
origin under an active support grant (docs/tickets/support-access.md)."""
import asyncio
from unittest.mock import AsyncMock, MagicMock

from services import telegram_listener as tl

ADMIN = {"user_id": "u-admin", "role": "admin", "telegram_chat_id": "1"}
OWNER_A = {"user_id": "u-a", "role": "viewer", "telegram_chat_id": "2"}
EDITOR_A = {"user_id": "u-ed", "role": "viewer", "telegram_chat_id": "3"}
VIEWER_A = {"user_id": "u-view", "role": "viewer", "telegram_chat_id": "4"}
OWNER_B = {"user_id": "u-b", "role": "viewer", "telegram_chat_id": "5"}
USERS = [ADMIN, OWNER_A, EDITOR_A, VIEWER_A, OWNER_B]
ORIGIN_A = {"id": "origin-a", "admin_user_id": "u-a", "editor_user_ids": {"u-ed"}, "viewer_user_ids": ["u-view"]}


def ids(users):
    return sorted(u["user_id"] for u in users)


def test_recipients_are_the_origins_team_only():
    assert ids(tl._alert_recipients(USERS, ORIGIN_A, False)) == ["u-a", "u-ed", "u-view"]


def test_admins_join_while_the_origin_grants_support():
    assert ids(tl._alert_recipients(USERS, ORIGIN_A, True)) == ["u-a", "u-admin", "u-ed", "u-view"]


def test_an_admin_on_the_team_receives_as_a_member():
    origin = {**ORIGIN_A, "viewer_user_ids": ["u-view", "u-admin"]}
    assert "u-admin" in ids(tl._alert_recipients(USERS, origin, False))


def test_other_tenant_never_receives_the_alert():
    assert "u-b" not in ids(tl._alert_recipients(USERS, ORIGIN_A, True))


def test_unattributed_alert_goes_to_admins_only():
    assert ids(tl._alert_recipients(USERS, {}, True)) == ["u-admin"]


def _run_dispatch(monkeypatch, origin_id, origin, grant=None):
    sent = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            sent.append(json["chat_id"])

    fake_db = MagicMock()
    fake_db.ALERTS_UNATTRIBUTED = "unattributed"
    fake_db.get_origin_id_for_domain.return_value = origin_id
    fake_db.get_origin_by_id.return_value = origin
    monkeypatch.setattr(tl, "db", fake_db)
    monkeypatch.setattr(tl, "BOT_TOKEN", "test-token")
    monkeypatch.setattr(tl, "_get_telegram_users", lambda: USERS)
    monkeypatch.setattr(tl.gemini_service, "explain_attack", AsyncMock(return_value="summary"))
    monkeypatch.setattr(tl.threat_intel, "record_pattern_hit_for_domain", lambda *a: None)
    monkeypatch.setattr(tl, "invalidate_alerts_cache", lambda: None)
    monkeypatch.setattr(tl.httpx, "AsyncClient", lambda **kw: FakeClient())
    from services import support_service
    monkeypatch.setattr(support_service, "active_grant", lambda oid: grant)
    monkeypatch.setattr(tl, "_last_push", {})  # same (origin, ip, rule) in every test: no cooldown carry-over
    asyncio.run(tl.dispatch_telegram_alert({"ip": "8.8.8.8", "url": "/x", "host": "shop-a.example", "status": 403}))
    return sorted(sent)


def test_dispatch_sends_only_to_the_alerts_origin_team(monkeypatch):
    assert _run_dispatch(monkeypatch, "origin-a", ORIGIN_A) == ["2", "3", "4"]


def test_dispatch_includes_admins_under_a_support_grant(monkeypatch):
    grant = {"grant_id": "g-1", "level": "read"}
    assert _run_dispatch(monkeypatch, "origin-a", ORIGIN_A, grant) == ["1", "2", "3", "4"]


def test_dispatch_for_unresolvable_host_reaches_admins_only(monkeypatch):
    assert _run_dispatch(monkeypatch, None, {}) == ["1"]
