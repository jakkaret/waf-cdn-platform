"""Per person and site: what Telegram tells you (services/notification_prefs.py),
the site's attack sensitivity, and the daily summary (services/daily_digest.py)."""
import asyncio
import datetime as dt
import uuid

import pytest

from db import pool
from services import alert_incidents as ai
from services import daily_digest
from services import notification_prefs as np_
from services import site_alerts as sa
from services import telegram_listener as tl
from services import tenant_service
from services.auth_service import AuthService

T0 = dt.datetime(2026, 10, 24, 3, 0, tzinfo=dt.timezone.utc)


@pytest.fixture()
def support(register_user):
    return register_user(email="support@example.com", username="support")  # first account = admin


@pytest.fixture()
def sent(monkeypatch):
    out = []

    async def fake_send(chat_ids, text, buttons=None):
        out.append({"chats": sorted(c for c in chat_ids if c), "text": text})
        return len(chat_ids)

    async def no_ai(stats):
        return None

    from services.gemini_service import gemini_service
    monkeypatch.setattr(tl, "send_telegram", fake_send)
    monkeypatch.setattr(gemini_service, "summarize_incident", no_ai)
    tl.invalidate_user_cache()
    return out


def _team(client, register_user, auth_header, tag):
    owner = register_user(email=f"own-{tag}@example.com", username=f"own_{tag}")
    editor = register_user(email=f"ed-{tag}@example.com", username=f"ed_{tag}")
    viewer = register_user(email=f"vw-{tag}@example.com", username=f"vw_{tag}")
    h = auth_header(owner["access_token"])
    oid = client.post("/api/origins", json={"label": f"shop {tag}", "ip": "203.0.113.50", "port": 8080}, headers=h).json()["id"]
    for u, role in ((editor, "editor"), (viewer, "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)", (oid, u["user"]["user_id"], role))
    svc = AuthService()
    for u, chat in ((owner, "1"), (editor, "2"), (viewer, "3")):
        svc.set_telegram_chat_id(u["user"]["user_id"], chat)
    tenant_service._TENANT_CACHE.clear()
    tl.invalidate_user_cache()
    return oid, owner, editor, viewer


def _alerts(origin_id, at, n, ip="198.51.100.7"):
    for k in range(n):
        pool.exec_("INSERT INTO alerts (alert_id, origin_id, domain, ip, url, status, attack_type, created_at) "
                   "VALUES (%s, %s, 'shop.example.com', %s, '/.env', '403', 'Restricted File Access Attempt', %s)",
                   (f"ALT-{uuid.uuid4().hex}", origin_id, ip, at + dt.timedelta(seconds=k * 280 / max(n, 1))))


def test_defaults_by_role():
    assert np_.effective("viewer", None) == {"attacks": True, "outages": False, "certs": False, "team": False, "digest": False}
    assert np_.effective("owner", None)["team"] is True
    assert np_.effective("editor", {"team": True})["team"] is False  # only the owner hears of team changes


def test_attacks_go_to_the_whole_team_unless_turned_off(client, register_user, auth_header, support, sent):
    oid, _owner, editor, _viewer = _team(client, register_user, auth_header, "a")
    np_.set_prefs(editor["user"]["user_id"], oid, "editor", {"attacks": False})
    _alerts(oid, T0, 60)
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=4, seconds=50)))
    assert sent[-1]["chats"] == ["1", "3"]


def test_outages_reach_viewers_only_when_they_turn_them_on(client, register_user, auth_header, support, sent):
    oid, _owner, _editor, viewer = _team(client, register_user, auth_header, "o")
    origin = tl.db.get_origin_by_id(oid)
    users = tl.recipients_for(oid, origin)
    assert sorted(u["telegram_chat_id"] for u in np_.filter_users(users, origin, "outages")) == ["1", "2"]
    np_.set_prefs(viewer["user"]["user_id"], oid, "viewer", {"outages": True})
    assert sorted(u["telegram_chat_id"] for u in np_.filter_users(users, origin, "outages")) == ["1", "2", "3"]


def test_sensitivity_moves_the_opening_threshold(client, register_user, auth_header, support, sent):
    oid, owner, _e, _v = _team(client, register_user, auth_header, "s")
    _alerts(oid, T0, 25, ip="192.0.2.1")  # 25 blocks, 25 from one IP
    at = T0 + dt.timedelta(minutes=4, seconds=50)
    assert ai.advance(at) == []  # medium: 50 / 30
    np_.set_sensitivity(oid, "high", owner["user"]["user_id"])  # high: 20 / 10
    assert [k for k, _ in ai.advance(at)] == ["open"]


def test_low_sensitivity_ignores_a_medium_burst(client, register_user, auth_header, support, sent):
    oid, owner, _e, _v = _team(client, register_user, auth_header, "l")
    np_.set_sensitivity(oid, "low", owner["user"]["user_id"])
    _alerts(oid, T0, 60)
    assert ai.advance(T0 + dt.timedelta(minutes=4, seconds=50)) == []


# ---- API --------------------------------------------------------------------

def test_preferences_api_lists_my_sites_and_saves_what_my_role_may_change(client, register_user, auth_header, support, sent):
    oid, owner, editor, viewer = _team(client, register_user, auth_header, "p")
    h = auth_header(viewer["access_token"])
    body = client.get("/api/alerts/preferences", headers=h).json()
    assert body["telegram_connected"] is True
    site = body["sites"][0]
    assert site["origin_id"] == oid and site["role"] == "viewer" and site["can_set_sensitivity"] is False
    assert site["prefs"]["outages"] is False and "team" not in site["changeable"]

    resp = client.put(f"/api/alerts/preferences/{oid}", json={"outages": True, "team": True}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["prefs"]["outages"] is True and resp.json()["prefs"]["team"] is False

    stranger = register_user(email="x@example.com", username="x")
    assert client.put(f"/api/alerts/preferences/{oid}", json={"attacks": False},
                      headers=auth_header(stranger["access_token"])).status_code == 404


def test_viewers_cannot_change_sensitivity_and_an_editors_change_reaches_the_owner(client, register_user, auth_header, support, sent):
    oid, owner, editor, viewer = _team(client, register_user, auth_header, "e")
    assert client.put(f"/api/alerts/sensitivity/{oid}", json={"sensitivity": "high"},
                      headers=auth_header(viewer["access_token"])).status_code == 403
    assert client.put(f"/api/alerts/sensitivity/{oid}", json={"sensitivity": "loud"},
                      headers=auth_header(editor["access_token"])).status_code == 422
    resp = client.put(f"/api/alerts/sensitivity/{oid}", json={"sensitivity": "high"},
                      headers=auth_header(editor["access_token"]))
    assert resp.status_code == 200
    assert np_.sensitivities([oid]) == {oid: "high"}
    assert asyncio.run(sa.team_tick()) == 1
    assert any(m["chats"] == ["1"] and "ตั้งความไวการแจ้งเตือนการโจมตีเป็น สูง" in m["text"] for m in sent)


# ---- daily digest -----------------------------------------------------------

def test_digest_is_sent_once_after_eight_about_yesterday(client, register_user, auth_header, support, sent):
    oid, owner, editor, _viewer = _team(client, register_user, auth_header, "d")
    np_.set_prefs(owner["user"]["user_id"], oid, "owner", {"digest": True})
    yesterday = dt.datetime(2026, 10, 23, 12, 0, tzinfo=ai.BKK)
    _alerts(oid, yesterday, 12, ip="192.0.2.5")
    _alerts(oid, yesterday - dt.timedelta(days=1), 3, ip="192.0.2.6")

    seven = dt.datetime(2026, 10, 24, 7, 59, tzinfo=ai.BKK)
    assert asyncio.run(daily_digest.tick(seven)) == 0
    eight = dt.datetime(2026, 10, 24, 8, 1, tzinfo=ai.BKK)
    assert asyncio.run(daily_digest.tick(eight)) == 1
    msg = sent[-1]
    assert msg["chats"] == ["1"]  # editor did not turn it on
    assert "สรุปเมื่อวาน · shop d</b> (23/10)" in msg["text"]
    assert "บล็อก <b>12</b> ครั้ง (วันก่อนหน้า 3) · 1 IP" in msg["text"]
    assert asyncio.run(daily_digest.tick(eight + dt.timedelta(hours=3))) == 0


def test_no_digest_after_leaving_the_team(client, register_user, auth_header, support, sent):
    oid, _owner, editor, _viewer = _team(client, register_user, auth_header, "g")
    np_.set_prefs(editor["user"]["user_id"], oid, "editor", {"digest": True})
    pool.exec_("DELETE FROM origin_members WHERE origin_id = %s AND user_id = %s", (oid, editor["user"]["user_id"]))
    assert asyncio.run(daily_digest.tick(dt.datetime(2026, 10, 24, 9, 0, tzinfo=ai.BKK))) == 0


# ---- test message -----------------------------------------------------------

@pytest.fixture()
def test_sends(monkeypatch):
    from api import alerts as alerts_module
    out = []
    reply = {"failure": None}

    async def fake_send_to(chat_id, text, buttons=None):
        out.append({"chat": chat_id, "text": text})
        return reply["failure"]

    monkeypatch.setattr(tl, "send_telegram_to", fake_send_to)
    alerts_module._last_test.clear()
    return out, reply


def test_test_message_goes_only_to_me_and_lists_what_i_receive(client, register_user, auth_header, support, sent, test_sends):
    out, _reply = test_sends
    oid, _owner, _editor, viewer = _team(client, register_user, auth_header, "t")
    np_.set_prefs(viewer["user"]["user_id"], oid, "viewer", {"digest": True})
    h = auth_header(viewer["access_token"])
    resp = client.post("/api/alerts/test", headers=h)
    assert resp.status_code == 200
    assert [m["chat"] for m in out] == ["3"]
    assert "ทดสอบการแจ้งเตือน" in out[0]["text"]
    assert "<b>shop t</b> (Viewer): การโจมตี, สรุปรายวัน" in out[0]["text"]
    assert "Support" not in out[0]["text"]
    assert sent == []  # nobody else on the team is messaged

    again = client.post("/api/alerts/test", headers=h)
    assert again.status_code == 429 and "นาทีละครั้ง" in again.json()["detail"]
    assert len(out) == 1


def test_test_message_needs_a_linked_telegram(client, register_user, auth_header, support, sent, test_sends):
    out, _reply = test_sends
    loner = register_user(email="loner@example.com", username="loner")
    resp = client.post("/api/alerts/test", headers=auth_header(loner["access_token"]))
    assert resp.status_code == 400 and resp.json()["detail"] == "ยังไม่ได้เชื่อม Telegram"
    assert out == []


def test_test_message_explains_a_blocked_bot(client, register_user, auth_header, support, sent, test_sends):
    _out, reply = test_sends
    _oid, owner, _e, _v = _team(client, register_user, auth_header, "b")
    reply["failure"] = "Forbidden: bot was blocked by the user"
    resp = client.post("/api/alerts/test", headers=auth_header(owner["access_token"]))
    assert resp.status_code == 400 and "บล็อกบอท" in resp.json()["detail"]


def test_support_sees_what_it_receives_as_support(client, register_user, auth_header, support, sent, test_sends):
    out, _reply = test_sends
    AuthService().set_telegram_chat_id(support["user"]["user_id"], "9")
    resp = client.post("/api/alerts/test", headers=auth_header(support["access_token"]))
    assert resp.status_code == 200
    assert "<b>Support</b>: เหตุการณ์ที่ระบุเว็บไม่ได้" in out[0]["text"]


def test_send_telegram_to_reports_telegrams_reason(monkeypatch):
    import httpx

    def handler(request):
        if b'"chat_id":"blocked"' in request.content.replace(b" ", b""):
            return httpx.Response(403, json={"ok": False, "description": "Forbidden: bot was blocked by the user"})
        return httpx.Response(200, json={"ok": True})

    real = httpx.AsyncClient
    monkeypatch.setattr(tl.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(tl, "BOT_TOKEN", "test-token")
    assert asyncio.run(tl.send_telegram_to("blocked", "hi")) == "Forbidden: bot was blocked by the user"
    assert asyncio.run(tl.send_telegram_to("42", "hi")) is None
    assert asyncio.run(tl.send_telegram(["42", "blocked", ""], "hi")) == 1
    monkeypatch.setattr(tl, "BOT_TOKEN", None)
    assert asyncio.run(tl.send_telegram_to("42", "hi")) == "no bot"
