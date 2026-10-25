"""
Rate limiting after P2.6 (security audit run 1, R1).

The dashboard's /api/limiter/check was never run by nginx (an auth_request
inside another auth_request's subrequest), so the rules set on the dashboard
had no effect. The limit now runs in control-api (cdn/control-api/
rate_limit.py, tested in cdn/control-api/tests/test_shield_phase2.py:
matching, per-rule buckets, static assets, fail-open, 429). The dashboard
keeps the rules in PostgreSQL and publishes them to Redis for control-api.

These tests cover the dashboard side: the old endpoint is gone, the rules are
published on every change, and the admin views read control-api's counters.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture()
def rl_client(app):
    from api import rate_limits
    app.include_router(rate_limits.router)
    return TestClient(app)


@pytest.fixture()
def admin_user(rl_client, register_user, auth_header):
    body = register_user(email="first-admin@example.com", username="first_admin")  # first user = admin
    return {"headers": auth_header(body["access_token"])}


def _published():
    import redis
    raw = redis.Redis().get("waf:ratelimit:rules")
    return json.loads(raw) if raw else None


def test_old_limiter_endpoint_is_gone():
    from main import app as main_app
    client = TestClient(main_app)  # no `with`: startup workers stay off
    headers = {"X-Original-URI": "/api/auth/login"}
    assert client.get("/api/limiter/check", headers=headers).status_code == 404
    # Only the SPA's GET catch-all is left on that path, so other methods get 405.
    assert client.post("/api/limiter/check", headers=headers).status_code == 405


def test_rules_are_published_for_control_api():
    from services.rate_limit_service import RateLimitService
    service = RateLimitService()
    service.publish_rules()
    published = {r["id"]: r for r in _published()}
    # migration 0002's three seeded rules, enabled
    assert {"rule_auth_protect", "rule_global_api", "rule_edge_flood"} <= set(published)
    assert published["rule_auth_protect"] == {
        "id": "rule_auth_protect", "name": "Authentication Brute-Force Guard", "path_pattern": "/api/auth/*",
        "method": "POST", "limit_count": 10, "window_seconds": 60, "enabled": 1, "origin_id": None,
    }


def test_every_rule_change_is_published(rl_client, admin_user):
    client = rl_client
    created = client.post("/api/rate-limits/rules", headers=admin_user["headers"], json={
        "name": "login", "path_pattern": "/login", "method": "POST", "limit_count": 5, "window_seconds": 60,
    }).json()["rule"]
    assert created["id"] in {r["id"] for r in _published()}

    client.put(f"/api/rate-limits/rules/{created['id']}", headers=admin_user["headers"], json={"enabled": 0})
    assert created["id"] not in {r["id"] for r in _published()}  # disabled rules are not enforced

    client.put(f"/api/rate-limits/rules/{created['id']}", headers=admin_user["headers"], json={"enabled": 1, "limit_count": 7})
    assert {r["id"]: r for r in _published()}[created["id"]]["limit_count"] == 7

    client.delete(f"/api/rate-limits/rules/{created['id']}", headers=admin_user["headers"])
    assert created["id"] not in {r["id"] for r in _published()}


def test_throttled_view_and_reset_read_control_apis_counters(rl_client, admin_user):
    client = rl_client
    import redis
    r = redis.Redis()
    r.set("rate:limit:rule_auth_protect:198.51.100.7", 12, ex=40)
    r.set("rate:limit:rule_edge_flood:198.51.100.7", 3, ex=1)
    r.set("rate:limit:rule_edge_flood:2001:db8::1", 1, ex=1)
    r.zadd("rate:limit:ml-suggest:user-1", {"x": 1})  # a per-user quota, not a client bucket

    clients = client.get("/api/rate-limits/throttled", headers=admin_user["headers"]).json()["throttled_clients"]
    by_key = {(c["rule_id"], c["ip"]): c for c in clients}
    assert set(by_key) == {("rule_auth_protect", "198.51.100.7"), ("rule_edge_flood", "198.51.100.7"),
                           ("rule_edge_flood", "2001:db8::1")}
    assert by_key[("rule_auth_protect", "198.51.100.7")]["status"] == "throttled"  # 12 > 10
    assert by_key[("rule_edge_flood", "198.51.100.7")]["status"] == "active"

    resp = client.post("/api/rate-limits/reset-client", headers=admin_user["headers"], json={"ip": "198.51.100.7"})
    assert resp.json()["status"] == "success"
    assert not r.exists("rate:limit:rule_auth_protect:198.51.100.7", "rate:limit:rule_edge_flood:198.51.100.7")
    assert r.exists("rate:limit:rule_edge_flood:2001:db8::1", "rate:limit:ml-suggest:user-1") == 2


# --------------------------------------------------------------- fail-safe

def test_redis_failure_fails_open_by_design():
    """RedisRateLimiter (still used for the per-user quotas in api/onboarding.py
    and api/ml.py) fails OPEN on a Redis error unless the caller asks for
    fail_open=False. No real Redis connection is made."""
    from services.rate_limiter import RedisRateLimiter

    rl = RedisRateLimiter.__new__(RedisRateLimiter)  # skip __init__'s real redis.Redis(...) construction
    rl.redis_client = MagicMock()
    rl.script_runner = MagicMock(side_effect=Exception("connection refused"))

    assert rl.is_allowed(ip="1.2.3.4", limit=10, window_seconds=60) == (True, 0, 0)
    assert rl.is_allowed(ip="1.2.3.4", limit=10, window_seconds=60, fail_open=False)[0] is False
