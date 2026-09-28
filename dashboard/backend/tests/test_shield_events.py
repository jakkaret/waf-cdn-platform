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


# ------------------------------------------------ config models and defaults

from pydantic import ValidationError  # noqa: E402

from api.origins import CaptchaShieldConfig, OtpShieldConfig  # noqa: E402
from services import captcha_config, otp_config  # noqa: E402


def test_allowlist_entries_are_normalised_and_validated():
    cfg = OtpShieldConfig(enabled=True, access_mode="allowlist",
                          allowed_emails=[" Boss@Gmail.com ", "@kku.ac.th", "boss@gmail.com", ""])
    assert cfg.allowed_emails == ["boss@gmail.com", "@kku.ac.th"]
    for bad in (["not-an-email"], ["@nodot"], ["a@b"], ["a b@c.com"]):
        with pytest.raises(ValidationError):
            OtpShieldConfig(enabled=True, access_mode="allowlist", allowed_emails=bad)


def test_enabled_allowlist_needs_at_least_one_entry():
    with pytest.raises(ValidationError):
        OtpShieldConfig(enabled=True, access_mode="allowlist", allowed_emails=[])
    OtpShieldConfig(enabled=False, access_mode="allowlist", allowed_emails=[])  # a draft is fine


def test_exclude_paths_must_be_absolute():
    with pytest.raises(ValidationError):
        CaptchaShieldConfig(exclude_paths=["wp-admin/admin-ajax.php"])
    assert CaptchaShieldConfig(exclude_paths=["/wp-admin/admin-ajax.php "]).exclude_paths == ["/wp-admin/admin-ajax.php"]


class _KV:
    def __init__(self, data):
        self.data = data

    def get(self, key):
        return self.data.get(key)


@pytest.mark.parametrize("module", [captcha_config, otp_config])
def test_new_config_starts_in_log_only_but_saved_one_keeps_enforcing(module, monkeypatch):
    store = {}
    monkeypatch.setattr(module, "_client", lambda: _KV(store))
    assert module.get_origin_config("fresh")["mode"] == "log_only"
    store[module._key_origin("old")] = json.dumps({"enabled": True, "login_paths": ["/login*"]})
    assert module.get_origin_config("old")["mode"] == "enforce"
    store[module._key_origin("chosen")] = json.dumps({"enabled": True, "mode": "log_only"})
    assert module.get_origin_config("chosen")["mode"] == "log_only"


# ---------------------------------------------------------------- preview


def test_preview_builds_a_parameterised_query_scoped_to_the_hosts():
    seen = []
    ch = MagicMock()

    def query(sql, parameters=None):
        seen.append((sql, parameters))
        if "GROUP BY user_agent" in sql:
            return MagicMock(result_rows=[("okhttp/4.9", 7)])
        return MagicMock(result_rows=[(20, 12, 8, 7)])

    ch.client.query.side_effect = query
    out = se.preview_for_paths(ch, ["a.test"], ["/wp-admin*", "/wp-login.php"], ["/wp-admin/admin-ajax.php"], 168)
    assert out == {"hours": 168, "total": 20, "get_head": 12, "other_methods": 8, "non_browser": 7,
                   "top_non_browser": [{"user_agent": "okhttp/4.9", "count": 7}]}
    sql, params = seen[0]
    assert params["hosts"] == ["a.test"]
    assert params["p0"] == "/wp-admin%" and params["p1"] == "/wp-login.php"
    assert params["x0"] == "/wp-admin/admin-ajax.php"
    assert "a.test" not in sql and "wp-admin" not in sql  # values only ever travel as parameters


def test_preview_with_no_verified_domain_never_queries():
    ch = MagicMock()
    assert se.preview_for_paths(ch, [], ["/login*"], [], 168)["total"] == 0
    ch.client.query.assert_not_called()


def test_like_escapes_sql_wildcards():
    assert se._like("/a_b%*") == "/a\\_b\\%%"


def test_preview_endpoint_is_for_origin_admins(client, accounts, monkeypatch):
    origin_id, admin_h, viewer_h, stranger_h = accounts
    ch = MagicMock()
    ch.connected = True
    monkeypatch.setattr(shield_events_api, "ch", ch)
    captured = {}
    monkeypatch.setattr(shield_events_api, "preview_for_paths",
                        lambda _ch, hosts, paths, excl, hours: captured.update(hosts=hosts) or {"total": 0})
    import services.origin_service as origin_service_module
    origin_service_module.db.domains_table.put_item(Item={"id": "d-ok", "origin_id": origin_id, "domain_name": "Shop.Example.com", "dns_verified": True})
    origin_service_module.db.domains_table.put_item(Item={"id": "d-no", "origin_id": origin_id, "domain_name": "pending.example.com", "dns_verified": False})
    body = {"login_paths": ["/login*"]}
    url = f"/api/origins/{origin_id}/shield-events/preview"
    assert client.post(url, json=body, headers=admin_h).status_code == 200
    assert captured["hosts"] == ["shop.example.com"]  # verified domains only
    assert client.post(url, json=body, headers=viewer_h).status_code == 403
    assert client.post(url, json=body, headers=stranger_h).status_code == 403
    assert client.post(url, json={"login_paths": ["login"]}, headers=admin_h).status_code == 400
