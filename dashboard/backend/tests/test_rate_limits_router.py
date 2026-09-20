"""
Scenario: api/rate_limits.py had no test coverage at all. Its write endpoints
(POST/PUT/DELETE /rules, POST /reset-client) are require_admin-only; reads
(GET /rules, GET /throttled) are require_viewer_or_above.

Same explicit, informed exception as test_ip_rules_router.py: the user was
told services.rate_limit_service.RateLimitService.__init__ touches the real
dashboard/backend/data/rate_limits.db as a module-level side effect of
importing api.rate_limits at all, and explicitly approved touching that real
file "as long as it doesn't break the system". Unlike ip_rules_service,
RateLimitService's write paths never call anything nginx-related (verified
by reading every method in services/rate_limit_service.py) -- pure SQLite
CRUD, plus Redis calls that already fail closed/empty when Redis is
unreachable (get_throttled_clients returns [], reset_client_limit returns
False), which is the case in this dev/test environment. Every rule this file
creates is deleted again (via its returned rule_id) in a finally block, so
the real DB is left exactly as it was found regardless of pass/fail.

This module defines its own `app`/`client` fixtures, same pattern as
test_domains_router.py / test_ip_rules_router.py.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import rate_limits as rate_limits_module

# A URI pattern that will never collide with anything real, marking it
# unmistakably as pytest's own so accidental survival is easy to spot too.
TEST_PATH_PATTERN = "/__pytest_rate_limit_probe__/*"


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(rate_limits_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def cleanup_test_rules():
    """Tests append the rule_id they created here; always deleted from the
    real store on teardown, pass or fail."""
    created_ids = []
    yield created_ids
    for rule_id in created_ids:
        rate_limits_module.service.delete_rule(rule_id)


def _create_rule(client, headers, **overrides):
    payload = {
        "name": "pytest probe rule",
        "path_pattern": TEST_PATH_PATTERN,
        "method": "ALL",
        "limit_count": 5,
        "window_seconds": 60,
    }
    payload.update(overrides)
    return client.post("/api/rate-limits/rules", json=payload, headers=headers)


def test_viewer_can_list_rules_but_not_create_one(client: TestClient, register_user, auth_header):
    admin = register_user(email="rl-admin1@example.com", username="rl_admin1")
    viewer = register_user(email="rl-viewer1@example.com", username="rl_viewer1")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.get("/api/rate-limits/rules", headers=viewer_headers)
    assert resp.status_code == 200
    assert "rules" in resp.json()

    resp = _create_rule(client, viewer_headers)
    assert resp.status_code == 403


def test_admin_create_update_delete_round_trips_through_the_real_store(
    client: TestClient, register_user, auth_header, cleanup_test_rules
):
    admin = register_user(email="rl-admin2@example.com", username="rl_admin2")
    headers = auth_header(admin["access_token"])

    resp = _create_rule(client, headers, limit_count=5, window_seconds=60)
    assert resp.status_code == 200, resp.text
    rule = resp.json()["rule"]
    cleanup_test_rules.append(rule["id"])

    listed = client.get("/api/rate-limits/rules", headers=headers).json()["rules"]
    assert any(r["id"] == rule["id"] and r["limit_count"] == 5 for r in listed)

    resp = client.put(
        f"/api/rate-limits/rules/{rule['id']}",
        json={"limit_count": 10},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["rule"]["limit_count"] == 10

    resp = client.delete(f"/api/rate-limits/rules/{rule['id']}", headers=headers)
    assert resp.status_code == 200
    cleanup_test_rules.clear()  # already deleted; nothing left for teardown to do

    listed_after = client.get("/api/rate-limits/rules", headers=headers).json()["rules"]
    assert not any(r["id"] == rule["id"] for r in listed_after)


def test_updating_a_nonexistent_rule_returns_404(client: TestClient, register_user, auth_header):
    admin = register_user(email="rl-admin3@example.com", username="rl_admin3")
    headers = auth_header(admin["access_token"])

    resp = client.put(
        "/api/rate-limits/rules/rule_does_not_exist",
        json={"limit_count": 1},
        headers=headers,
    )
    assert resp.status_code == 404


def test_deleting_a_nonexistent_rule_returns_404(client: TestClient, register_user, auth_header):
    admin = register_user(email="rl-admin4@example.com", username="rl_admin4")
    headers = auth_header(admin["access_token"])

    resp = client.delete("/api/rate-limits/rules/rule_does_not_exist", headers=headers)
    assert resp.status_code == 404


def test_reset_client_requires_admin(client: TestClient, register_user, auth_header):
    admin = register_user(email="rl-admin5@example.com", username="rl_admin5")
    viewer = register_user(email="rl-viewer5@example.com", username="rl_viewer5")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.post("/api/rate-limits/reset-client", json={"ip": "203.0.113.251"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_reset_client_with_no_active_bucket_reports_info_not_an_error(
    client: TestClient, register_user, auth_header
):
    """Redis is unreachable in this dev/test environment, so
    reset_client_limit() returns False (no bucket found) rather than
    raising -- the endpoint must surface that as a 200 'info' response, not
    a 500."""
    admin = register_user(email="rl-admin6@example.com", username="rl_admin6")
    headers = auth_header(admin["access_token"])

    resp = client.post("/api/rate-limits/reset-client", json={"ip": "203.0.113.251"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "info"


def test_throttled_clients_endpoint_requires_only_viewer(client: TestClient, register_user, auth_header):
    admin = register_user(email="rl-admin7@example.com", username="rl_admin7")
    viewer = register_user(email="rl-viewer7@example.com", username="rl_viewer7")
    resp = client.get("/api/rate-limits/throttled", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    assert "throttled_clients" in resp.json()
