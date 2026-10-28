"""
Shared pytest fixtures for the backend test suite.

Tests run in-process against fastapi.testclient.TestClient. The control-plane
store is a real, throwaway PostgreSQL database built from db/migrations
(tests/pg_harness.py; TEST_DATABASE_URL must point at a disposable server) and
emptied before every test. Redis is fakeredis, ClickHouse and docker/nginx are
stubbed at their service boundary, and no network call leaves the machine.
"""
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1. Environment must be nailed down before *any* api/services module import.
#    dotenv's load_dotenv() (called by several modules) never overrides an
#    already-set variable, so setting these first also shields the suite from
#    a real dashboard/backend/../.env (or CI's own env) leaking in.
# ---------------------------------------------------------------------------
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-pytest-only"
os.environ["SESSION_COOKIE_SECURE"] = "false"  # TestClient uses http; let Set-Cookie come back
# Production seeds its first admin (scripts/seed_admin.py) and never lets
# self-registration grant admin. The suite keeps the old bootstrap rule (the
# first registered user is admin) that its fixtures are written around;
# tests/test_register_role.py covers the production default.
os.environ["WAF_FIRST_USER_ADMIN"] = "true"
os.environ["FRP_AUTH_TOKEN"] = "test-frp-token-for-pytest-only"
os.environ["WAF_CONTAINER_NAME"] = "test-waf-container-does-not-exist"
os.environ["GEMINI_API_KEY"] = ""
os.environ.setdefault("ORIGINS_QUOTA_DEFAULT", "5")
# DNS checks ask the domain's nameservers directly in production; tests stay on
# the resolver path they always used. tests/test_dns_authoritative.py turns it on
# with fake nameservers.
os.environ["WAF_DNS_AUTHORITATIVE"] = "0"
# Same for the on-demand HTTPS probe of the progress page (real TLS to an edge).
os.environ["WAF_HTTPS_PROBE"] = "0"
# Services keep sqlite/json state in dashboard/backend/data/, which is tracked in
# git and is live data on Main. Tests get a throwaway directory instead.
import tempfile  # noqa: E402
os.environ["WAF_DATA_DIR"] = tempfile.mkdtemp(prefix="waf-test-data-")

BACKEND_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# 1b. Redis: every redis.Redis(...) the application builds -- including the
#     module-level ones created at import (rate_limit_service, rate_limiter) --
#     gets an in-memory fakeredis sharing one server, emptied before each test.
#     Without this the suite silently used whatever Redis answered on
#     127.0.0.1:6379: on the production host that was the live Redis
#     (found 2026-09-29 when 10 tests failed in a clean container).
# ---------------------------------------------------------------------------
import fakeredis  # noqa: E402
import redis as _redis_module  # noqa: E402

_FAKE_REDIS_SERVER = fakeredis.FakeServer()


class _SharedFakeRedis(fakeredis.FakeRedis):
    def __init__(self, *args, **kwargs):
        kwargs["server"] = _FAKE_REDIS_SERVER
        super().__init__(*args, **kwargs)


_redis_module.Redis = _SharedFakeRedis
_redis_module.StrictRedis = _SharedFakeRedis

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# ---------------------------------------------------------------------------
# 1c. PostgreSQL: one throwaway database per test run (tests/pg_harness.py),
#     emptied before every test by fake_infrastructure below.
# ---------------------------------------------------------------------------
from tests import pg_harness  # noqa: E402

if not pg_harness.enabled():
    pytest.exit("TEST_DATABASE_URL is required: the suite runs on a disposable PostgreSQL "
                "(e.g. postgresql://postgres@127.0.0.1:55432/postgres)", returncode=4)
pg_harness.ensure_database()


def pytest_configure(config):
    config.addinivalue_line("markers", "pg: needs a real PostgreSQL (TEST_DATABASE_URL)")
    config.addinivalue_line("markers", "no_auto_accept: invitations stay pending until the test accepts them")
    config.addinivalue_line("markers", "email_unverified: accounts stay unverified (the real email check runs)")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402

from services.rate_limiter import limiter  # noqa: E402
from services.dynamodb_service import DynamoDBService  # noqa: E402
import services.origin_service as origin_service_module  # noqa: E402
import services.tenant_service as tenant_service_module  # noqa: E402
import services.rbac as rbac_module  # noqa: E402

from api import auth as auth_module  # noqa: E402
from api import origins as origins_module  # noqa: E402
from api import rules as rules_module  # noqa: E402
from api import ai_summary as ai_summary_module  # noqa: E402
from api import domains as domains_module  # noqa: E402
from api import managed_rules as managed_rules_module  # noqa: E402
from api import alerts as alerts_module  # noqa: E402
from api import tunnels as tunnels_module  # noqa: E402
import services.public_status as public_status_module  # noqa: E402


@pytest.fixture(autouse=True)
def fake_infrastructure(monkeypatch, tmp_path):
    """Fresh state for every test: empty database tables (default rate-limit
    rules re-seeded), empty fakeredis, and every non-database boundary
    stubbed (Ruling R3). Module-level store singletons (db = DynamoDBService()
    in many modules) all reach the same test database through db.pool, so
    they need no patching."""
    _SharedFakeRedis().flushall()
    pg_harness.reset()

    # origin_service keeps process-wide, in-memory caches (live FRP proxy
    # list; origins scan; per-user origins) -- reset them so one test's cached
    # result never survives into the next.
    monkeypatch.setattr(origin_service_module, "_LIVE_PROXIES_CACHE", None)
    monkeypatch.setattr(origin_service_module, "_ORIGINS_SCAN_CACHE", None)
    monkeypatch.setattr(origin_service_module, "_USER_ORIGINS_CACHE", {})
    monkeypatch.setattr(tenant_service_module, "_TENANT_CACHE", {})

    # Rule files/nginx: rule_manager is instantiated at import time against
    # the *real* modsecurity/custom-rules directory, and reload/test shell
    # out to `docker exec` against WAF_CONTAINER_NAME, which does not exist
    # here. Redirect writes to a throwaway directory and no-op the two
    # docker-exec-backed calls.
    monkeypatch.setattr(rules_module.rule_manager, "rules_dir", str(tmp_path))
    monkeypatch.setattr(rules_module.rule_manager, "test_nginx", lambda: None)
    monkeypatch.setattr(rules_module.rule_manager, "reload_nginx", lambda: None)
    # api.tenant_rules and api.managed_rules both import this same rule_manager
    # instance (services/tenant_rules.py, services/managed_ruleset.py), so the
    # three patches above already cover them.

    # Direct-mode site routes: verify/delete endpoints schedule
    # reconcile_site_routes() in the background, which shells out to `docker
    # exec`. No-op it here; tests of the reconcile itself call the function
    # they imported directly and fake _docker.
    from services import nginx_site_service as nginx_site_module
    monkeypatch.setattr(nginx_site_module, "reconcile_site_routes", lambda: {})
    monkeypatch.setattr(nginx_site_module, "_deployed_domains", set())
    monkeypatch.setattr(nginx_site_module, "_failed_domains", {})
    monkeypatch.setattr(nginx_site_module, "_pending_restores", {})
    monkeypatch.setattr(nginx_site_module, "_reload_pending", False)
    monkeypatch.setattr(nginx_site_module, "_unreloaded", set())

    # ML gate map (services/ml_gate.py): written into a throwaway directory,
    # nginx test/reload through the no-op rule_manager above.
    from services import ml_gate as ml_gate_module
    monkeypatch.setattr(ml_gate_module, "MAP_DIR", tmp_path / "ml-gate")
    monkeypatch.setattr(ml_gate_module, "_rule_manager", rules_module.rule_manager)
    monkeypatch.setattr(ml_gate_module, "_state", {"last_error": None, "applied_at": None})

    # Deception layer: its audit logger lazily builds a real ClickHouseService
    # (production credentials). Without this, every test
    # that hits /api/deception/respond wrote fake attack rows into the live
    # access_logs / security_audit_logs (happened 2026-09-27). Swap the classes
    # the module constructs *and* the already-built singleton's sinks.
    from services import deception_service as deception_module

    class _NoClickHouse:
        connected = False
        client = None

        def save_log(self, *_args, **_kwargs):
            return False

    monkeypatch.setattr(deception_module, "ClickHouseService", _NoClickHouse)
    monkeypatch.setattr(deception_module.deception_service, "_ch", _NoClickHouse())

    # The Origins list overview (services/origin_overview.py) builds a real
    # ClickHouseService on first use; never let a test reach a real store.
    from services import origin_overview as origin_overview_module
    monkeypatch.setattr(origin_overview_module, "_CH", _NoClickHouse())

    # Rate limiter storage is a module-level singleton shared across the
    # whole test session; reset it so one test's register/login calls never
    # trip another test's 5-per-minute/10-per-minute limits.
    limiter.reset()

    yield


@pytest.fixture()
def app() -> FastAPI:
    """A minimal app wired with just the routers these scenarios exercise."""
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(rules_module.router)
    test_app.include_router(ai_summary_module.router)
    from api import invites as invites_module
    test_app.include_router(invites_module.router)
    test_app.include_router(alerts_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    from api import site_access as site_access_module
    test_app.include_router(site_access_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def db() -> DynamoDBService:
    """The store (PgStore) on the test database, emptied before each test."""
    return DynamoDBService()


DEFAULT_PASSWORD = "Sup3rSecret!"


@pytest.fixture()
def default_password() -> str:
    return DEFAULT_PASSWORD


@pytest.fixture()
def register_user(client: TestClient):
    """Factory fixture: register_user(email, username, role="viewer") -> body dict.

    Note: the *first* user ever registered against a given fake store always
    becomes admin (api/auth.py's own bootstrap rule), regardless of the role
    requested here.
    """

    def _register(email: str, username: str, role: str = "viewer",
                   password: str = DEFAULT_PASSWORD) -> dict:
        resp = client.post(
            "/api/auth/register",
            json={"email": email, "username": username, "password": password, "role": role},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    return _register


@pytest.fixture()
def auth_header():
    def _header(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    return _header


@pytest.fixture(autouse=True)
def invite_mailbox(request, monkeypatch):
    """Origin sharing is by emailed invitation (N9/H64). This fake mailbox
    records every invitation instead of sending it. Unless a test is marked
    no_auto_accept, the person who owns that address (an account registered
    with it) "clicks the link" at once, so tests about other features can set
    up a viewer/editor in one call as before."""
    from services import auth_service as auth_mod
    from services import invite_service

    sent = []

    def fake_send(to_addr, origin_label, role, link):
        token = link.split("token=", 1)[1]
        sent.append({"to": to_addr, "role": role, "link": link, "token": token})
        if request.node.get_closest_marker("no_auto_accept") is None:
            user = auth_mod.AuthService().get_user_by_email(to_addr)
            if user:
                invite_service.accept_invite(token, user["user_id"])
                from services.tenant_service import invalidate_tenant_cache
                invalidate_tenant_cache(user["user_id"])
        return True

    monkeypatch.setattr(invite_service, "send_invite_email", fake_send)
    return sent


@pytest.fixture(autouse=True)
def _ai_quota_allows_by_default(monkeypatch):
    """fakeredis has no Lua, so the real RedisRateLimiter would fail closed
    (429) in every test that calls copilot or summarize-range. Tests of the
    quota itself (test_ai_quota_audit2.py) install their own limiter."""
    import services.ai_quota as ai_quota

    class _AllowAll:
        def is_allowed(self, *a, **k):
            return True, 999, 0

    monkeypatch.setattr(ai_quota, "_limiter", _AllowAll())


@pytest.fixture(autouse=True)
def code_mailbox(monkeypatch):
    """Verification and reset codes (services/email_codes.py) land here
    instead of an SMTP server."""
    from services import email_codes

    sent = []

    def fake_send(to_addr, purpose, code):
        sent.append({"to": to_addr, "purpose": purpose, "code": code})
        return True

    monkeypatch.setattr(email_codes, "send_code_email", fake_send)
    return sent


@pytest.fixture(autouse=True)
def _email_verified_by_default(request, monkeypatch):
    """Tests about other features act as an owner who already confirmed the
    emailed code (the suite creates most users straight in the database).
    Tests marked email_unverified run the real check (tests/test_email_verification.py)."""
    if request.node.get_closest_marker("email_unverified") is None:
        monkeypatch.setattr(rbac_module, "email_verified", lambda user: True)
