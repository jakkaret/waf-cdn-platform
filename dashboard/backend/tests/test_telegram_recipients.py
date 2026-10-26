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


def test_recipients_for_unattributed_traffic_is_support_only(monkeypatch):
    monkeypatch.setattr(tl, "_get_telegram_users", lambda: USERS)
    assert ids(tl.recipients_for(tl.db.ALERTS_UNATTRIBUTED, {})) == ["u-admin"]


def test_recipients_for_a_site_follows_its_support_grant(monkeypatch):
    from services import support_service
    monkeypatch.setattr(tl, "_get_telegram_users", lambda: USERS)
    monkeypatch.setattr(support_service, "active_grant", lambda oid: None)
    assert ids(tl.recipients_for("origin-a", ORIGIN_A)) == ["u-a", "u-ed", "u-view"]
    monkeypatch.setattr(support_service, "active_grant", lambda oid: {"grant_id": "g-1", "level": "read"})
    assert ids(tl.recipients_for("origin-a", ORIGIN_A)) == ["u-a", "u-admin", "u-ed", "u-view"]


def test_a_blocked_request_is_stored_but_never_pushed_or_sent_to_ai(monkeypatch):
    """Telegram goes out per incident (services/alert_incidents.py)."""
    stored, posted = [], []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            posted.append(url)

    fake_db = MagicMock()
    fake_db.ALERTS_UNATTRIBUTED = "unattributed"
    fake_db.get_origin_id_for_domain.return_value = "origin-a"
    fake_db.put_alert.side_effect = stored.append
    monkeypatch.setattr(tl, "db", fake_db)
    monkeypatch.setattr(tl, "BOT_TOKEN", "test-token")
    monkeypatch.setattr(tl, "invalidate_alerts_cache", lambda: None)
    monkeypatch.setattr(tl.httpx, "AsyncClient", lambda **kw: FakeClient())
    from services.gemini_service import gemini_service
    monkeypatch.setattr(gemini_service, "explain_attack", AsyncMock(side_effect=AssertionError("no AI per request")))
    asyncio.run(tl.record_alert({"ip": "8.8.8.8", "url": "/x", "host": "shop-a.example", "status": 403}))
    assert posted == []
    assert len(stored) == 1 and stored[0]["origin_id"] == "origin-a" and stored[0]["ai_summary"] is None
