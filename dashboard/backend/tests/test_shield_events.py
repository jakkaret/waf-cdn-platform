"""services/shield_events.py (Redis queue -> ClickHouse) and the per-origin
read API. No real Redis or ClickHouse: both are faked."""
import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api import auth as auth_module
from api import origins as origins_module
from api import shield_events as shield_events_api
from services import shield_events as se
from services.rate_limiter import limiter


class FakeList:
    def __init__(self, items):
        self.items = list(items)  # index 0 = newest (LPUSH side)

    def rpop(self, _key, count):
        out = []
        while self.items and len(out) < count:
            out.append(self.items.pop())
        return out or None

    def rpush(self, _key, *values):
        self.items.extend(values)


def _event(i, **kw):
    return json.dumps({"ts": 1790000000 + i, "kind": "otp", "event": "otp_verified", "host": "a.test",
                       "origin_id": "o1", "client_ip": "198.51.100.7", "email_masked": "al***@gmail.com",
                       "email_hash": "abc", "path": "/login", **kw})


def test_drain_moves_oldest_first_into_clickhouse():
    q = FakeList([_event(2), _event(1), _event(0)])
    ch = MagicMock()
    assert se.drain_once(q, ch) == 3
    table, rows = ch.client.insert.call_args.args
    assert table == "shield_events"
    from datetime import timezone
    assert [r[0] for r in rows] == [datetime.fromtimestamp(1790000000 + i, tz=timezone.utc).replace(tzinfo=None) for i in range(3)]
    assert rows[0][1:] == ["o1", "a.test", "otp", "otp_verified", "198.51.100.7", "al***@gmail.com", "abc", "/login"]
    assert q.items == []


def test_drain_puts_the_batch_back_when_insert_fails():
    original = [_event(2), _event(1), _event(0)]
    q = FakeList(original)
    ch = MagicMock()
    ch.client.insert.side_effect = RuntimeError("clickhouse down")
    with pytest.raises(RuntimeError):
        se.drain_once(q, ch)
    assert q.items == original  # same order: the next drain retries oldest first


def test_drain_skips_malformed_items():
    q = FakeList([_event(1), "not json", _event(0)])
    ch = MagicMock()
    assert se.drain_once(q, ch) == 3
    assert len(ch.client.insert.call_args.args[1]) == 2


def test_drain_empty_queue_does_nothing():
    ch = MagicMock()
    assert se.drain_once(FakeList([]), ch) == 0
    ch.client.insert.assert_not_called()


# --------------------------------------------------------------------- HTTP


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    for module in (auth_module, origins_module, shield_events_api):
        test_app.include_router(module.router)
    return test_app


@pytest.fixture()
def fake_ch(monkeypatch):
    seen = []
    ch = MagicMock()
    ch.connected = True

    def query(sql, parameters=None):
        seen.append((sql, parameters))
        if sql.startswith("SELECT kind"):
            return MagicMock(result_rows=[("otp", "otp_verified", 3)])
        return MagicMock(result_rows=[(datetime(2026, 9, 29, 1, 0), "a.test", "otp", "otp_verified",
                                       "198.51.100.7", "al***@gmail.com", "/login")])

    ch.client.query.side_effect = query
    monkeypatch.setattr(shield_events_api, "ch", ch)
    return seen


@pytest.fixture()
def accounts(client, register_user, auth_header):
    register_user(email="se-platform@example.com", username="se_platform")
    admin = register_user(email="se-admin@example.com", username="se_admin", role="viewer")
    viewer = register_user(email="se-viewer@example.com", username="se_viewer", role="viewer")
    stranger = register_user(email="se-stranger@example.com", username="se_stranger", role="viewer")
    admin_h, viewer_h, stranger_h = (auth_header(u["access_token"]) for u in (admin, viewer, stranger))
    origin_id = client.post("/api/origins", json={"label": "SE", "ip": "203.0.113.80", "port": 80}, headers=admin_h).json()["id"]
    assert client.post(f"/api/origins/{origin_id}/viewers", json={"email": "se-viewer@example.com"}, headers=admin_h).status_code == 200
    return origin_id, admin_h, viewer_h, stranger_h


def test_admin_and_viewer_read_their_origin_only(client, accounts, fake_ch):
    origin_id, admin_h, viewer_h, stranger_h = accounts
    for h in (admin_h, viewer_h):
        resp = client.get(f"/api/origins/{origin_id}/shield-events?hours=24", headers=h)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["counts"] == [{"kind": "otp", "event": "otp_verified", "label": "Verified", "count": 3}]
        assert body["recent"][0]["email"] == "al***@gmail.com"
    assert all(p["origin_id"] == origin_id for _sql, p in fake_ch)
    assert all("{origin_id:String}" in sql for sql, _p in fake_ch)

    before = len(fake_ch)
    assert client.get(f"/api/origins/{origin_id}/shield-events", headers=stranger_h).status_code == 403
    assert len(fake_ch) == before  # a stranger never reaches ClickHouse
