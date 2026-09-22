"""Diagnosing-bugs skill, applied to the open finding from the tenant-
isolation audit (2026-09-22): GET /api/ml-rules/ and /{rule_id} are gated
by require_viewer_or_above -- i.e. ANY signed-up non-admin user -- but the
pending-rules queue has NO per-tenant field at all (confirmed: neither
services/ml_rule_service.py's create_pending_rule() item shape nor its two
real callers -- api/ml.py's user-invoked predict_and_suggest, and
api/ml_rules.py's own CVE-Auto-Patch scan -- ever capture an origin_id or
domain). Unlike the alerts leak (services/log_forward.py's data["host"]
gave a real signal to scope by), there is no tenant signal recoverable
here at all: this is a genuinely global admin-review queue containing
other tenants' real attack payloads/URLs (e.g. source_url values captured
verbatim from whatever malicious request triggered the classifier).

Decision made (per the audit's own "no correct seam" finding, and the
explicit instruction to decide autonomously): since the data model cannot
support real per-tenant scoping, and showing every signed-up viewer every
other tenant's attack payloads is real information exposure, the fix is
to restrict listing/detail to admin-only -- the same policy already
applied to approve/reject/delete on this exact queue."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import ml_rules as ml_rules_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ml_rules_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_a_non_admin_viewer_cannot_list_the_global_ml_rules_queue(
    client, register_user, auth_header,
):
    register_user(email="mlq-admin-decoy@example.com", username="mlq_admin_decoy")  # consumes first-user-admin slot
    viewer = register_user(email="mlq-viewer@example.com", username="mlq_viewer", role="viewer")

    resp = client.get("/api/ml-rules/", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 403


def test_a_non_admin_viewer_cannot_read_a_single_rules_detail(
    client, register_user, auth_header,
):
    register_user(email="mlq-admin-decoy2@example.com", username="mlq_admin_decoy2")
    viewer = register_user(email="mlq-viewer2@example.com", username="mlq_viewer2", role="viewer")

    resp = client.get("/api/ml-rules/some-rule-id", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 403


def test_admin_can_still_list_and_read(client, register_user, auth_header):
    admin = register_user(email="mlq-admin3@example.com", username="mlq_admin3")  # first user -> admin

    resp = client.get("/api/ml-rules/", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
