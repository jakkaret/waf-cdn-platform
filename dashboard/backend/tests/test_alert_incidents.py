"""Attack incidents (services/alert_incidents.py): one burst of blocked
requests opens one incident and costs two Telegram messages (open, close),
never one per block. Recipients follow the site's team; Support only for
unattributed traffic or a site under a support grant."""
import asyncio
import datetime as dt
import uuid

import pytest

from db import pool
from services import alert_incidents as ai
from services import telegram_listener as tl

T0 = dt.datetime(2026, 10, 21, 10, 0, tzinfo=dt.timezone.utc)

# 5-minute buckets on Main, 21-23 Oct 2026: [bucket index, demo1, demo2].
# The three bursts (315, 109, 315) each came from one IP.
REAL_BUCKETS = [[1429,17,0],[1430,2,0],[1431,4,0],[1437,2,0],[1439,2,0],[1440,5,0],[1448,4,0],[1449,2,0],
                [1450,2,0],[1451,2,0],[1460,1,0],[1472,0,16],[1476,0,2],[1478,0,8],[1483,0,2],[1484,0,5],
                [1485,0,1],[1487,0,2],[1494,0,2],[1502,2,0],[1503,2,0],[1529,0,2],[1616,1,0],[1617,1,0],
                [1633,12,0],[1659,0,1],[1668,0,1],[1688,1,0],[1698,1,1],[1716,1,0],[1725,0,12],[1732,0,1],
                [1741,1,0],[1768,2,0],[1772,0,1],[1777,1,0],[1809,315,0],[1905,0,2],[1906,0,2],[1907,109,0],
                [1935,1,0],[1950,2,0],[1954,0,315],[1970,0,18],[2003,1,0],[2015,0,1]]


def _origin(client, register_user, auth_header, email, label):
    user = register_user(email=email, username=email.split("@")[0].replace("-", "_"))
    resp = client.post("/api/origins", json={"label": label, "ip": "203.0.113.10", "port": 8080},
                       headers=auth_header(user["access_token"]))
    assert resp.status_code == 200, resp.text
    return user, resp.json()["origin_id"]


def _alerts(origin_id, at, n, ip="198.51.100.7", attack="Restricted File Access Attempt", url="/.env"):
    for k in range(n):
        pool.exec_("INSERT INTO alerts (alert_id, origin_id, domain, ip, url, status, attack_type, created_at) "
                   "VALUES (%s, %s, 'shop.example.com', %s, %s, '403', %s, %s)",
                   (f"ALT-{uuid.uuid4().hex}", origin_id, ip, url, attack, at + dt.timedelta(seconds=k * 280 / max(n, 1))))


def _advance(at):
    return ai.advance(at)


@pytest.fixture()
def admin(register_user):
    return register_user(email="support@example.com", username="support")  # first account = admin


def test_the_real_burst_pattern_becomes_three_incidents(client, register_user, auth_header, admin):
    _u1, demo1 = _origin(client, register_user, auth_header, "d1@example.com", "demo1")
    _u2, demo2 = _origin(client, register_user, auth_header, "d2@example.com", "demo2")
    base = T0 - dt.timedelta(minutes=5 * 1429)
    for i, a, b in REAL_BUCKETS:
        at = base + dt.timedelta(minutes=5 * i)
        for oid, n in ((demo1, a), (demo2, b)):
            if n:
                big = n >= 100
                _alerts(oid, at, n, ip="198.51.100.7" if big else f"192.0.2.{i % 200}")

    kinds = []
    t = T0
    end = base + dt.timedelta(minutes=5 * 2016 + 45)
    while t <= end:
        kinds += [k for k, _inc in _advance(t)]
        t += dt.timedelta(minutes=1)
    assert kinds.count("open") == 3
    assert kinds.count("close") == 3
    assert kinds.count("escalate") == 0
    rows = pool.q("SELECT blocked_count, ip_count FROM alert_incidents ORDER BY opened_at")
    assert [r["blocked_count"] for r in rows] == [315, 109, 315]
    assert all(r["ip_count"] == 1 for r in rows)


def test_a_trickle_never_opens(client, register_user, auth_header, admin):
    _u, oid = _origin(client, register_user, auth_header, "t@example.com", "shop")
    _alerts(oid, T0, 29, ip="192.0.2.1")
    _alerts(oid, T0, 20, ip="192.0.2.2")
    assert _advance(T0 + dt.timedelta(minutes=4)) == []


def test_many_ips_reaching_the_total_open_one(client, register_user, auth_header, admin):
    _u, oid = _origin(client, register_user, auth_header, "m@example.com", "shop")
    for k in range(50):
        _alerts(oid, T0, 1, ip=f"192.0.2.{k}")
    assert [k for k, _ in _advance(T0 + dt.timedelta(minutes=4))] == ["open"]


def test_one_ip_reaching_its_threshold_opens(client, register_user, auth_header, admin):
    _u, oid = _origin(client, register_user, auth_header, "o@example.com", "shop")
    _alerts(oid, T0, 30)
    events = _advance(T0 + dt.timedelta(minutes=4, seconds=50))
    assert [k for k, _ in events] == ["open"]
    assert events[0][1]["scope"] == oid


def test_a_burst_older_than_the_window_is_never_reported(client, register_user, auth_header, admin):
    """First start after deploy: yesterday's bursts stay quiet."""
    _u, oid = _origin(client, register_user, auth_header, "old@example.com", "shop")
    _alerts(oid, T0, 300)
    assert _advance(T0 + dt.timedelta(hours=1)) == []


def test_each_transition_is_reported_once(client, register_user, auth_header, admin):
    _u, oid = _origin(client, register_user, auth_header, "once@example.com", "shop")
    _alerts(oid, T0, 60)
    at = T0 + dt.timedelta(minutes=4, seconds=50)
    assert [k for k, _ in _advance(at)] == ["open"]
    assert _advance(at) == []  # a second worker, or a restart, finds nothing new
    later = T0 + dt.timedelta(minutes=40)
    assert [k for k, _ in _advance(later)] == ["close"]
    assert _advance(later) == []


def test_an_incident_ten_times_its_opening_size_is_reported_once_more(client, register_user, auth_header, admin):
    _u, oid = _origin(client, register_user, auth_header, "esc@example.com", "shop")
    _alerts(oid, T0, 50)
    assert [k for k, _ in _advance(T0 + dt.timedelta(minutes=4, seconds=50))] == ["open"]
    for m in range(1, 11):
        _alerts(oid, T0 + dt.timedelta(minutes=5 * m), 50, ip=f"192.0.2.{m}")
    assert [k for k, _ in _advance(T0 + dt.timedelta(minutes=54))] == ["escalate"]
    _alerts(oid, T0 + dt.timedelta(minutes=55), 50, ip="192.0.2.99")
    assert _advance(T0 + dt.timedelta(minutes=59)) == []


def test_traffic_for_no_site_has_its_own_incident(admin):
    _alerts(None, T0, 40)
    events = _advance(T0 + dt.timedelta(minutes=4, seconds=50))
    assert [(k, inc["scope"]) for k, inc in events] == [("open", "unattributed")]


# ---- messages and recipients ------------------------------------------------

def _capture(monkeypatch, summary=None):
    sent = []

    async def fake_send(chat_ids, text, buttons=None):
        sent.append({"chats": sorted(chat_ids), "text": text, "buttons": buttons})
        return len(chat_ids)

    async def fake_summary(stats):
        return summary

    monkeypatch.setattr(tl, "send_telegram", fake_send)
    from services.gemini_service import gemini_service
    monkeypatch.setattr(gemini_service, "summarize_incident", fake_summary)
    tl.invalidate_user_cache()
    return sent


def test_messages_go_to_the_sites_team_only_and_name_the_site(client, register_user, auth_header, admin, monkeypatch):
    from services.auth_service import AuthService
    svc = AuthService()
    owner_a, origin_a = _origin(client, register_user, auth_header, "a@example.com", "<b>shop</b> A")
    owner_b, _origin_b = _origin(client, register_user, auth_header, "b@example.com", "shop B")
    svc.set_telegram_chat_id(owner_a["user"]["user_id"], "111")
    svc.set_telegram_chat_id(owner_b["user"]["user_id"], "222")
    svc.set_telegram_chat_id(admin["user"]["user_id"], "999")
    sent = _capture(monkeypatch)

    _alerts(origin_a, T0, 60, url="/<script>")
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=4, seconds=50)))
    assert len(sent) == 1
    msg = sent[0]
    assert msg["chats"] == ["111"]  # not tenant B, not Support (no grant)
    assert "&lt;b&gt;shop&lt;/b&gt; A กำลังถูกโจมตี" in msg["text"]
    assert "Node" not in msg["text"] and "<script>" not in msg["text"]
    assert msg["buttons"][0][1].endswith("/alerts?incident=" + pool.q1("SELECT incident_id::text i FROM alert_incidents")["i"])

    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=40)))
    assert len(sent) == 2
    assert "เหตุการณ์จบแล้ว" in sent[1]["text"]
    assert "AI" not in sent[1]["text"]  # Gemini did not answer: numbers only, no AI label
    row = pool.q1("SELECT open_notified_at, close_notified_at, summary, summary_by_ai FROM alert_incidents")
    assert row["open_notified_at"] and row["close_notified_at"]
    assert row["summary"] is None and row["summary_by_ai"] is False


def test_the_close_message_carries_the_ai_summary_when_there_is_one(client, register_user, auth_header, admin, monkeypatch):
    from services.auth_service import AuthService
    owner, origin = _origin(client, register_user, auth_header, "s@example.com", "shop")
    AuthService().set_telegram_chat_id(owner["user"]["user_id"], "111")
    sent = _capture(monkeypatch, summary="บอตไล่หาไฟล์ตั้งค่า\nควรทำ: ไม่ต้องทำอะไรเพิ่ม")
    _alerts(origin, T0, 60)
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=4, seconds=50)))
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=40)))
    assert "สรุปโดย AI" in sent[-1]["text"] and "ควรทำ:" in sent[-1]["text"]
    assert pool.q1("SELECT summary_by_ai FROM alert_incidents")["summary_by_ai"] is True


def test_support_is_told_only_under_a_grant_or_for_unattributed_traffic(client, register_user, auth_header, admin, monkeypatch):
    from services.auth_service import AuthService
    AuthService().set_telegram_chat_id(admin["user"]["user_id"], "999")
    _owner, origin = _origin(client, register_user, auth_header, "g@example.com", "shop")
    sent = _capture(monkeypatch)

    _alerts(None, T0, 40)
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=4, seconds=50)))
    assert sent[-1]["chats"] == ["999"]
    assert "traffic ที่ไม่ตรงกับเว็บไหน" in sent[-1]["text"]

    t = pool.q1("INSERT INTO support_tickets (origin_id, subject) VALUES (%s, 's') RETURNING ticket_id", (origin,))
    pool.exec_("INSERT INTO support_grants (ticket_id, origin_id, level, expires_at) "
               "VALUES (%s, %s, 'viewer', now() + interval '1 hour')", (t["ticket_id"], origin))
    _alerts(origin, T0, 40)
    asyncio.run(ai.tick(T0 + dt.timedelta(minutes=4, seconds=55)))
    assert sent[-1]["chats"] == ["999"]


# ---- API --------------------------------------------------------------------

def test_incidents_api_shows_only_the_callers_sites(client, register_user, auth_header, admin):
    from services.tenant_service import invalidate_admin_scope_cache
    owner_a, origin_a = _origin(client, register_user, auth_header, "ia@example.com", "shop A")
    owner_b, _origin_b = _origin(client, register_user, auth_header, "ib@example.com", "shop B")
    _alerts(origin_a, T0, 60)
    _alerts(None, T0, 60)
    _advance(T0 + dt.timedelta(minutes=4, seconds=50))
    inc_a = pool.q1("SELECT incident_id::text i FROM alert_incidents WHERE scope = %s", (origin_a,))["i"]
    invalidate_admin_scope_cache()

    def seen(user, **params):
        resp = client.get("/api/alerts/incidents", params=params, headers=auth_header(user["access_token"]))
        assert resp.status_code == 200, resp.text
        return [i["scope"] for i in resp.json()["incidents"]]

    assert seen(owner_a) == [origin_a]
    assert seen(owner_b) == []
    assert seen(owner_b, incident=inc_a) == []  # the Telegram link does not open another tenant's incident
    assert seen(admin) == ["unattributed"]
    resp = client.get("/api/alerts/incidents", headers=auth_header(owner_a["access_token"]))
    assert resp.json()["incidents"][0]["label"] == "shop A"
