"""Alerts someone has to act on (services/site_alerts.py): a site its visitors
cannot reach, an expiring certificate, and changes made by someone other
than the owner. Each is told once, to the people who can fix it."""
import asyncio
import datetime as dt

import pytest

from db import pool
from services import audit_log
from services import site_alerts as sa
from services import telegram_listener as tl
from services.auth_service import AuthService

T0 = dt.datetime(2026, 10, 24, 3, 0, tzinfo=dt.timezone.utc)


def _site(client, register_user, auth_header, email, label, domain):
    user = register_user(email=email, username=email.split("@")[0].replace("-", "_"))
    h = auth_header(user["access_token"])
    resp = client.post("/api/origins", json={"label": label, "ip": "203.0.113.50", "port": 8080}, headers=h)
    assert resp.status_code == 200, resp.text
    origin_id = resp.json()["id"]
    resp = client.post(f"/api/origins/{origin_id}/domains", json={"domain_name": domain}, headers=h)
    assert resp.status_code == 200, resp.text
    from services.dynamodb_service import DynamoDBService
    DynamoDBService().claim_verified_domain(resp.json()["domain"]["domain_id"])
    return user, origin_id


class FakeCH:
    connected = True

    def __init__(self, window, day=None):
        self.window, self.day = window, day or {}
        outer = self

        class _Client:
            def query(self, sql, parameters=None):
                class R:
                    pass
                r = R()
                if "count() AS t" in sql:
                    r.result_rows = [(h, e, t) for h, (e, t) in outer.window.items()]
                else:
                    r.result_rows = list(outer.day.items())
                return r

        self.client = _Client()


@pytest.fixture()
def support(register_user):
    return register_user(email="support@example.com", username="support")  # first account = admin


@pytest.fixture()
def sent(monkeypatch):
    out = []

    async def fake_send(chat_ids, text, buttons=None):
        out.append({"chats": sorted(c for c in chat_ids if c), "text": text, "buttons": buttons})
        return len(chat_ids)

    monkeypatch.setattr(tl, "send_telegram", fake_send)
    monkeypatch.setattr(sa, "_tunnel_offline_since", {})
    tl.invalidate_user_cache()
    return out


def _run(now, ch):
    return asyncio.run(sa.outage_tick(now, ch))


def test_a_site_answering_5xx_is_down_once_then_back(client, register_user, auth_header, support, sent):
    owner, oid = _site(client, register_user, auth_header, "own@example.com", "shop", "shop.example.com")
    AuthService().set_telegram_chat_id(owner["user"]["user_id"], "111")

    assert [k for k, _ in _run(T0, FakeCH({"shop.example.com": (8, 10)}))] == ["down"]
    assert "shop: ผู้เข้าเว็บเปิดเว็บไม่ได้" in sent[-1]["text"] and "8 จาก 10" in sent[-1]["text"]
    assert sent[-1]["chats"] == ["111"]
    assert sent[-1]["buttons"][0][1].endswith(f"/origins/{oid}")
    assert _run(T0 + dt.timedelta(minutes=1), FakeCH({"shop.example.com": (9, 9)})) == []  # still down, no repeat
    assert [k for k, _ in _run(T0 + dt.timedelta(minutes=3), FakeCH({"shop.example.com": (0, 12)}))] == ["up"]
    assert "shop กลับมาใช้งานได้" in sent[-1]["text"]
    assert len(sent) == 2


def test_a_few_errors_among_many_answers_are_not_an_outage(client, register_user, auth_header, support, sent):
    _site(client, register_user, auth_header, "few@example.com", "shop", "few.example.com")
    assert _run(T0, FakeCH({"few.example.com": (4, 4)})) == []        # under the minimum
    assert _run(T0, FakeCH({"few.example.com": (10, 100)})) == []     # under half
    assert sent == []


def test_an_outage_with_no_traffic_left_closes_after_quiet(client, register_user, auth_header, support, sent):
    _site(client, register_user, auth_header, "q@example.com", "shop", "q.example.com")
    _run(T0, FakeCH({"q.example.com": (6, 6)}))
    assert _run(T0 + dt.timedelta(minutes=20), FakeCH({})) == []
    events = _run(T0 + dt.timedelta(minutes=31), FakeCH({}))
    assert [(k, o["how"]) for k, o in events] == [("up", "quiet")]


def test_outage_goes_to_owner_and_editors_not_viewers_or_other_tenants(client, register_user, auth_header, support, sent):
    owner, oid = _site(client, register_user, auth_header, "o2@example.com", "shop", "o2.example.com")
    other, _ = _site(client, register_user, auth_header, "x2@example.com", "other", "x2.example.com")
    viewer = register_user(email="v2@example.com", username="v2")
    pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, 'viewer')",
               (oid, viewer["user"]["user_id"]))
    svc = AuthService()
    for u, chat in ((owner, "1"), (other, "2"), (viewer, "3"), (support, "9")):
        svc.set_telegram_chat_id(u["user"]["user_id"], chat)
    from services.origin_service import _invalidate_origins_caches
    _invalidate_origins_caches()
    _run(T0, FakeCH({"o2.example.com": (6, 6)}))
    assert sent[-1]["chats"] == ["1"]


def test_an_offline_tunnel_that_served_traffic_is_reported_after_two_checks(client, register_user, auth_header, support, sent):
    _owner, oid = _site(client, register_user, auth_header, "tun@example.com", "tunnel shop", "tun.example.com")
    tunnels = {oid: False}
    served = {oid: 50}
    assert sa.advance_outages(T0, {}, served, tunnels, mono=1000.0) == []
    events = sa.advance_outages(T0, {}, served, tunnels, mono=1000.0 + sa.TUNNEL_OFFLINE_CONFIRM_SECONDS)
    assert [(k, o["reason"]) for k, o in events] == [("down", "tunnel_offline")]
    events = sa.advance_outages(T0, {}, served, {oid: True}, mono=1300.0)
    assert [k for k, _ in events] == ["up"]


def test_a_tunnel_that_never_served_anyone_is_not_an_outage(client, register_user, auth_header, support, sent):
    _owner, oid = _site(client, register_user, auth_header, "new@example.com", "new", "new.example.com")
    assert sa.advance_outages(T0, {}, {}, {oid: False}, mono=1000.0) == []
    assert sa.advance_outages(T0, {}, {}, {oid: False}, mono=2000.0) == []


# ---- certificates -----------------------------------------------------------

def test_cert_warning_goes_to_the_domains_team_or_support_for_no_site(client, register_user, auth_header, support, sent):
    owner, _oid = _site(client, register_user, auth_header, "c@example.com", "shop", "cert.example.com")
    AuthService().set_telegram_chat_id(owner["user"]["user_id"], "111")
    AuthService().set_telegram_chat_id(support["user"]["user_id"], "999")
    asyncio.run(sa.notify_cert("cert.example.com", 7, "2026-10-31T00:00:00+00:00"))
    assert sent[-1]["chats"] == ["111"]
    assert "cert.example.com จะหมดอายุใน 7 วัน" in sent[-1]["text"]
    asyncio.run(sa.notify_cert("status.platform.example", -1, "2026-10-20"))
    assert sent[-1]["chats"] == ["999"] and "หมดอายุแล้ว" in sent[-1]["text"]


# ---- team changes -----------------------------------------------------------

def _audit(oid, actor, action, summary, now):
    audit_log.write_audit_event(oid, actor["user"]["user_id"], actor["user"]["username"], action, summary, now=now)


def test_owner_is_told_of_changes_by_others_once_and_not_of_their_own(client, register_user, auth_header, support, sent):
    owner, oid = _site(client, register_user, auth_header, "t@example.com", "shop", "team.example.com")
    editor = register_user(email="ed@example.com", username="ed")
    AuthService().set_telegram_chat_id(owner["user"]["user_id"], "111")
    AuthService().set_telegram_chat_id(editor["user"]["user_id"], "222")
    pool.exec_("DELETE FROM audit_notified")
    now = dt.datetime.now(dt.timezone.utc)
    sa.claim_team_events(now)  # what _site itself audited (by the owner) is out of the way
    _audit(oid, editor, "domain.create", "เพิ่มโดเมน: new.team.example.com", now)
    _audit(oid, support, "origin.update", "แก้ไข origin: ip", now)
    _audit(oid, owner, "domain.delete", "ลบโดเมน: old.team.example.com", now)
    assert asyncio.run(sa.team_tick(now)) == 2
    assert [m["chats"] for m in sent] == [["111"], ["111"]]
    texts = sorted(m["text"] for m in sent)  # same millisecond: either order
    assert any("มีการเปลี่ยนแปลงโดย ed\n" in t and "เพิ่มโดเมน: new.team.example.com" in t for t in texts)
    assert any("มีการเปลี่ยนแปลงโดย support (Support)" in t for t in texts)
    assert asyncio.run(sa.team_tick(now)) == 0  # each event once


def test_old_audit_events_are_not_replayed(client, register_user, auth_header, support, sent):
    _owner, oid = _site(client, register_user, auth_header, "old@example.com", "shop", "old.example.com")
    editor = register_user(email="ed2@example.com", username="ed2")
    then = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    _audit(oid, editor, "domain.create", "เพิ่มโดเมน: a.example.com", then)
    assert asyncio.run(sa.team_tick()) == 0


def test_the_worker_builds_one_clickhouse_client_not_one_per_tick(monkeypatch):
    # ClickHouseService() runs the table DDL; building it every minute ran DDL every minute.
    from services import clickhouse_service
    built = []

    class FakeClickHouse:
        connected = True

        def __init__(self):
            built.append(self)

    monkeypatch.setattr(clickhouse_service, "ClickHouseService", FakeClickHouse)
    monkeypatch.setattr(sa, "_ch", None)
    assert sa._clickhouse() is sa._clickhouse() is sa._clickhouse()
    assert len(built) == 1
