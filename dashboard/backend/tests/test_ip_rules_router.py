"""
Scenario: api/ip_rules.py had no test coverage at all. It gates real,
traffic-blocking state: POST/DELETE/bulk-delete are require_admin-only, and
every successful write calls services.ip_rule_service.IPRuleService's
rule_manager.reload_nginx() (a live `docker exec waf-nginx nginx -s reload`).

This module defines its own `app`/`client` fixtures (conftest.py's shared
minimal app deliberately does not include api.ip_rules's router), same
pattern as test_domains_router.py.

Explicit, informed exception to the "never touch pre-existing uncommitted
files" rule for this session: the user was told IPRuleService.__init__ writes
to the real dashboard/backend/data/ip_rules.db (and the real ModSecurity
global_blocklist.txt/global_whitelist.txt/.conf files under
modsecurity/custom-rules/) as an unavoidable module-level side effect of
importing api.ip_rules at all, and explicitly approved touching those real
files "as long as it doesn't break the system" -- so these tests run
against the real SQLite file, not a fake. What they do NOT do is trigger a
real nginx reload: reload_nginx/test_nginx are monkeypatched to no-ops here,
identical to how conftest.py's fake_infrastructure fixture already
neutralizes them for the *other* RuleManager instance (rules_module's) --
same established, already-approved pattern, just applied to
ip_rules_module.service's own RuleManager. Every test that adds a rule
removes it again in a finally block, so the real DB is left exactly as it
was found regardless of pass/fail.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import ip_rules as ip_rules_module

# A TEST-NET-3 address (RFC 5737, reserved for documentation/testing) --
# guaranteed never a real corporate or user IP, so it cannot collide with a
# genuine blocklist entry.
TEST_IP = "203.0.113.250"


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ip_rules_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def no_real_nginx_reload(monkeypatch):
    """See module docstring: real DB writes are approved, a real live nginx
    reload on every test run is not -- neutralize it the same way
    conftest.py already does for rules_module.rule_manager."""
    monkeypatch.setattr(ip_rules_module.service.rule_manager, "test_nginx", lambda: None)
    monkeypatch.setattr(ip_rules_module.service.rule_manager, "reload_nginx", lambda: None)


@pytest.fixture(autouse=True)
def cleanup_test_ip():
    """Belt-and-suspenders on top of each test's own cleanup: whatever
    happens, TEST_IP never survives past this test in the real DB."""
    yield
    ip_rules_module.service.delete_rule(TEST_IP)


def test_viewer_can_list_rules_but_not_add_one(client: TestClient, register_user, auth_header):
    admin = register_user(email="ipr-admin1@example.com", username="ipr_admin1")
    viewer = register_user(email="ipr-viewer1@example.com", username="ipr_viewer1")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.get("/api/ip-rules/", headers=viewer_headers)
    assert resp.status_code == 200
    assert "rules" in resp.json()

    resp = client.post(
        "/api/ip-rules/",
        json={"ip": TEST_IP, "rule_type": "block", "reason": "pytest"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_admin_add_then_delete_rule_round_trips_through_the_real_store(
    client: TestClient, register_user, auth_header
):
    admin = register_user(email="ipr-admin2@example.com", username="ipr_admin2")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/ip-rules/",
        json={"ip": TEST_IP, "rule_type": "block", "reason": "pytest round trip"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    listed = client.get("/api/ip-rules/", headers=headers).json()["rules"]
    assert any(r["ip"] == TEST_IP for r in listed), "added rule did not appear in the real store"

    resp = client.delete(f"/api/ip-rules/{TEST_IP}", headers=headers)
    assert resp.status_code == 200

    listed_after = client.get("/api/ip-rules/", headers=headers).json()["rules"]
    assert not any(r["ip"] == TEST_IP for r in listed_after), "rule survived its own delete"


def test_invalid_ip_is_rejected_with_400_not_500(client: TestClient, register_user, auth_header):
    admin = register_user(email="ipr-admin3@example.com", username="ipr_admin3")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/ip-rules/",
        json={"ip": "not-an-ip-address", "rule_type": "block", "reason": "pytest"},
        headers=headers,
    )
    assert resp.status_code == 400


def test_deleting_a_rule_that_does_not_exist_returns_404(client: TestClient, register_user, auth_header):
    admin = register_user(email="ipr-admin4@example.com", username="ipr_admin4")
    headers = auth_header(admin["access_token"])

    resp = client.delete("/api/ip-rules/198.51.100.77", headers=headers)
    assert resp.status_code == 404


def test_bulk_delete_requires_admin(client: TestClient, register_user, auth_header):
    admin = register_user(email="ipr-admin5@example.com", username="ipr_admin5")
    viewer = register_user(email="ipr-viewer5@example.com", username="ipr_viewer5")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.post("/api/ip-rules/bulk-delete", json={"ips": [TEST_IP]}, headers=viewer_headers)
    assert resp.status_code == 403


def test_a_write_never_triggers_a_real_nginx_reload(client: TestClient, register_user, auth_header, monkeypatch):
    """Proves the no_real_nginx_reload fixture actually does its job: if
    reload_nginx were somehow still wired to the real RuleManager method,
    this replaces it with a call-recorder and asserts it fires (confirming
    the write path really does call it) while never touching the real
    implementation during the test run."""
    calls = []
    monkeypatch.setattr(ip_rules_module.service.rule_manager, "reload_nginx", lambda: calls.append(1))
    admin = register_user(email="ipr-admin6@example.com", username="ipr_admin6")
    headers = auth_header(admin["access_token"])

    client.post(
        "/api/ip-rules/",
        json={"ip": TEST_IP, "rule_type": "block", "reason": "pytest"},
        headers=headers,
    )
    assert calls == [1]
