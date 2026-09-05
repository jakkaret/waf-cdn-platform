"""
Scenario: dd614ac merged api/limiter.py's dynamic per-path rate-limit rules
and static-asset bypass with no accompanying tests.

Real Redis and the real rate_limits.db sqlite file are never touched here --
api.limiter.rate_limiter and api.limiter.rule_service are replaced with
controllable fakes, since (a) this dev/test environment has no Redis
reachable (confirmed throughout this session's other test files) and (b)
RateLimitService's DB_PATH is a fixed real project path
(dashboard/backend/data/rate_limits.db), not something a test should write
real rows into.

Findings derived from reading services/rate_limiter.py and
services/rate_limit_service.py, encoded as tests below:
  - RedisRateLimiter.is_allowed() fails OPEN on any Redis error (its own
    comment: "Fail-open: allow request if Redis fails") -- tested as
    documented behaviour, not something to silently "fix" to fail-closed,
    since that tradeoff (availability vs strict enforcement) is a real
    design choice already made explicit in the code.
  - The rate-limit key is `f"rate:limit:{ip}"` -- IP only. There is no
    tenant, origin, or user dimension in the key at all, so two different
    tenants' traffic from behind the same IP (e.g. NAT, shared office
    network) share one bucket, and a rule's path_pattern is the only way
    to scope limits at all (by URL shape, not identity).
  - The `burst` and `action` ("temp_ban") columns exist in the rate_rules
    schema and are returned by list_rules(), but check_rate_limit() never
    reads either one -- rules can only ever produce a plain 401, and the
    configured burst allowance has zero effect on the sliding window.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import limiter as limiter_module  # noqa: E402
from api.limiter import is_static_asset  # noqa: E402


@pytest.fixture
def app_client(monkeypatch):
    fake_rate_limiter = MagicMock()
    fake_rule_service = MagicMock()
    monkeypatch.setattr(limiter_module, "rate_limiter", fake_rate_limiter)
    monkeypatch.setattr(limiter_module, "rule_service", fake_rule_service)

    app = FastAPI()
    app.include_router(limiter_module.router)
    client = TestClient(app)
    return client, fake_rate_limiter, fake_rule_service


# --------------------------------------------------------------- static asset

@pytest.mark.parametrize("path", [
    "/assets/index-abc123.js",
    "/static/logo.png",
    "/styles.css",
    "/favicon.ico",
    "/app.js",
    "/photo.jpeg?v=2",
])
def test_is_static_asset_recognizes_static_paths(path):
    assert is_static_asset(path) is True


@pytest.mark.parametrize("path", [
    "/api/auth/login",
    "/api/origins",
    "/",
    "/dashboard",
])
def test_is_static_asset_does_not_flag_dynamic_paths(path):
    assert is_static_asset(path) is False


def test_static_asset_bypasses_rate_limiter_entirely(app_client):
    client, fake_rate_limiter, fake_rule_service = app_client
    resp = client.get("/api/limiter/check", headers={"X-Original-URI": "/assets/index-abc.js"})
    assert resp.status_code == 200
    assert resp.json()["type"] == "static_asset"
    fake_rate_limiter.is_allowed.assert_not_called()


# ------------------------------------------------------------- normal request

def test_normal_request_under_limit_is_allowed(app_client):
    client, fake_rate_limiter, fake_rule_service = app_client
    fake_rule_service.list_rules.return_value = []
    fake_rate_limiter.is_allowed.return_value = (True, 5, 0)

    resp = client.get("/api/limiter/check", headers={"X-Original-URI": "/api/origins"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "allowed"
    assert resp.headers["X-RateLimit-Limit"] == "100"  # module default when no rule matches


# --------------------------------------------------------- threshold exceeded

def test_threshold_exceeded_returns_401_with_retry_after(app_client):
    client, fake_rate_limiter, fake_rule_service = app_client
    fake_rule_service.list_rules.return_value = []
    fake_rate_limiter.is_allowed.return_value = (False, 100, 7)

    resp = client.get("/api/limiter/check", headers={"X-Original-URI": "/api/origins"})
    assert resp.status_code == 401
    assert resp.headers["Retry-After"] == "7"


def test_rule_specific_limit_is_applied_when_path_matches(app_client):
    """Derived from actual matching logic: exact path match wins; the rule's
    limit_count/window_seconds are passed straight to is_allowed()."""
    client, fake_rate_limiter, fake_rule_service = app_client
    fake_rule_service.list_rules.return_value = [
        {"enabled": 1, "method": "ALL", "path_pattern": "/api/auth/*", "limit_count": 10, "window_seconds": 60},
    ]
    fake_rate_limiter.is_allowed.return_value = (True, 1, 0)

    client.get("/api/limiter/check", headers={"X-Original-URI": "/api/auth/login"})

    fake_rate_limiter.is_allowed.assert_called_once()
    _, kwargs = fake_rate_limiter.is_allowed.call_args
    assert kwargs["limit"] == 10
    assert kwargs["window_seconds"] == 60


def test_disabled_rule_is_not_applied(app_client):
    client, fake_rate_limiter, fake_rule_service = app_client
    fake_rule_service.list_rules.return_value = [
        {"enabled": 0, "method": "ALL", "path_pattern": "/api/auth/*", "limit_count": 1, "window_seconds": 1},
    ]
    fake_rate_limiter.is_allowed.return_value = (True, 1, 0)

    client.get("/api/limiter/check", headers={"X-Original-URI": "/api/auth/login"})

    _, kwargs = fake_rate_limiter.is_allowed.call_args
    assert kwargs["limit"] == 100  # falls back to the module default, disabled rule ignored


# ----------------------------------------------------------- burst (unused)

def test_burst_field_has_no_effect_on_the_applied_limit():
    """Documents a real gap: `burst` exists in the rate_rules schema and is
    returned by list_rules(), but check_rate_limit() never reads
    rule.get("burst") anywhere -- a rule configured with a generous burst
    allowance behaves identically to one with burst=0. This is a config
    field with zero runtime effect, not a working burst-allowance feature.
    """
    import inspect
    source = inspect.getsource(limiter_module.check_rate_limit)
    assert "burst" not in source, (
        "expected 'burst' to be unused in check_rate_limit's body per the "
        "current implementation -- if this now fails, the burst field has "
        "been wired up and this test (and the finding it documents) is "
        "stale and should be rewritten to test the real behaviour instead"
    )


# --------------------------------------------------------- reset/expiry

def test_reset_expiry_is_the_sliding_window_itself_not_a_separate_mechanism():
    """RedisRateLimiter has no separate "reset" API surfaced through
    check_rate_limit -- the only expiry mechanism is the sliding window's
    own ZREMRANGEBYSCORE eviction inside the Lua script (verified by
    reading services/rate_limiter.py). RateLimitService.reset_client_limit()
    exists as an *admin* operation (a separate DELETE on the Redis key) but
    is not reachable from this endpoint at all -- confirms there is no
    per-request "expiry" concept beyond the window boundary itself.
    """
    import inspect
    limiter_source = inspect.getsource(limiter_module)
    assert "reset_client_limit" not in limiter_source


# ----------------------------------------------- per-tenant/origin isolation

def test_rate_limit_key_has_no_tenant_or_origin_dimension():
    """Derived directly from services/rate_limiter.py: the Redis key is
    f"rate:limit:{ip}" -- IP only. Two different tenants/origins sharing a
    client IP (NAT, shared office network, or two origins fronted by the
    same reverse proxy) share the exact same rate-limit bucket. This is a
    real architectural gap for "per-tenant/per-origin isolation", not a
    hypothesis -- confirmed by reading the key-construction code directly.
    """
    import inspect
    from services import rate_limiter as rate_limiter_service_module
    source = inspect.getsource(rate_limiter_service_module.RedisRateLimiter.is_allowed)
    assert 'f"rate:limit:{ip}"' in source, (
        "the rate-limit key format changed -- if it now includes a tenant/"
        "origin component, this test (and the finding it documents) is "
        "stale and should be rewritten to test the real per-tenant "
        "isolation behaviour instead"
    )


# --------------------------------------------------------------- fail-safe

def test_redis_failure_fails_open_by_design():
    """RedisRateLimiter.is_allowed() catches any exception and returns
    (True, 0, 0) -- i.e. FAILS OPEN, per its own comment. Tested directly
    against the real class (not a fake) since this is the actual documented
    behaviour to lock in, not something to fake around. No real Redis
    connection is made: redis-py's client is lazy, and the injected
    script_runner below raises before any socket I/O would occur.
    """
    from services.rate_limiter import RedisRateLimiter

    rl = RedisRateLimiter.__new__(RedisRateLimiter)  # skip __init__'s real redis.Redis(...) construction
    rl.redis_client = MagicMock()
    rl.script_runner = MagicMock(side_effect=Exception("connection refused"))

    is_allowed, current_count, retry_after = rl.is_allowed(ip="1.2.3.4", limit=10, window_seconds=60)

    assert is_allowed is True, "expected fail-OPEN on a Redis error, per the code's own documented design"
    assert current_count == 0
    assert retry_after == 0
