"""HTTP-level proof that Team Workspace (2026-09-22) works end to end
through real registered users and the real endpoints -- complements
tests/test_editor_role.py's direct rbac-function coverage (written first,
before any endpoint was wired, per the advisor review for this feature)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import origins as origins_module
from api import domains as domains_module
import services.audit_log as audit_log_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _patch_audit_log_db(monkeypatch, fake_infrastructure):
    """audit_log.py's own `db = DynamoDBService()` -- same gap class as
    every other module in the session's established list, patched here
    locally rather than in conftest.py since only this test file exercises
    endpoints that write audit events through the real HTTP path.

    fake_infrastructure (conftest, autouse) clears the shared _STORE dict --
    depending on it explicitly (rather than relying on same-scope autouse
    ordering, which is not guaranteed) forces that clear to happen BEFORE
    this fixture builds its FakeDynamoDBService, so waf_audit_log starts
    empty for every test in this file."""
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())


def _create_origin(client, token, auth_header, label="workspace-origin"):
    resp = client.post(
        "/api/origins", json={"label": label, "ip": "203.0.113.50", "port": 8080},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def test_an_editor_can_update_the_origin_but_a_viewer_cannot(
    client, register_user, auth_header,
):
    owner = register_user(email="ws-owner@example.com", username="ws_owner")
    editor = register_user(email="ws-editor@example.com", username="ws_editor")
    viewer = register_user(email="ws-viewer@example.com", username="ws_viewer")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])
    viewer_h = auth_header(viewer["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)

    grant = client.post(f"/api/origins/{origin_id}/editors", json={"email": "ws-editor@example.com"}, headers=owner_h)
    assert grant.status_code == 200, grant.text
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "ws-viewer@example.com"}, headers=owner_h)

    # Editor can update.
    resp = client.put(f"/api/origins/{origin_id}", json={"label": "renamed-by-editor"}, headers=editor_h)
    assert resp.status_code == 200, resp.text

    # Viewer cannot.
    resp = client.put(f"/api/origins/{origin_id}", json={"label": "renamed-by-viewer"}, headers=viewer_h)
    assert resp.status_code == 403


def test_an_origin_admin_can_delete_the_origin(client, register_user, auth_header):
    owner = register_user(email="ws-owner2@example.com", username="ws_owner2")
    editor = register_user(email="ws-editor2@example.com", username="ws_editor2")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "ws-editor2@example.com"}, headers=owner_h)

    resp = client.delete(f"/api/origins/{origin_id}", headers=editor_h)
    assert resp.status_code == 200


def test_an_origin_admin_can_manage_the_team_but_not_remove_the_creator(client, register_user, auth_header):
    owner = register_user(email="ws-owner3@example.com", username="ws_owner3")
    editor = register_user(email="ws-editor3@example.com", username="ws_editor3")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "ws-editor3@example.com"}, headers=owner_h)

    register_user(email="someone-else@example.com", username="someone_else")
    resp = client.post(f"/api/origins/{origin_id}/viewers", json={"email": "someone-else@example.com"}, headers=editor_h)
    assert resp.status_code == 200

    resp = client.post(f"/api/origins/{origin_id}/editors", json={"email": "someone-else@example.com"}, headers=editor_h)
    assert resp.status_code == 200

    resp = client.delete(f"/api/origins/{origin_id}/editors/{owner['user']['user_id']}", headers=editor_h)
    assert resp.status_code == 400


def test_an_editor_can_add_and_delete_a_domain(client, register_user, auth_header):
    owner = register_user(email="ws-owner4@example.com", username="ws_owner4")
    editor = register_user(email="ws-editor4@example.com", username="ws_editor4")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "ws-editor4@example.com"}, headers=owner_h)

    resp = client.post(
        f"/api/origins/{origin_id}/domains", json={"domain_name": "editor-added.waf-it-kku.online"}, headers=editor_h,
    )
    assert resp.status_code == 200, resp.text
    domain_id = resp.json()["domain"]["domain_id"]

    resp = client.delete(f"/api/origins/{origin_id}/domains/{domain_id}", headers=editor_h)
    assert resp.status_code == 200, resp.text


def test_origin_update_and_domain_create_write_real_audit_events(client, register_user, auth_header):
    owner = register_user(email="ws-owner5@example.com", username="ws_owner5")
    owner_h = auth_header(owner["access_token"])
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    client.put(f"/api/origins/{origin_id}", json={"label": "audited-rename"}, headers=owner_h)
    client.post(f"/api/origins/{origin_id}/domains", json={"domain_name": "audited.waf-it-kku.online"}, headers=owner_h)

    events = audit_log_module.get_audit_log(origin_id, db=audit_log_module.db)
    actions = [e["action"] for e in events]
    assert "origin.update" in actions
    assert "domain.create" in actions


def test_audit_log_endpoint_is_readable_by_owner_and_editor_but_not_a_stranger(
    client, register_user, auth_header,
):
    owner = register_user(email="ws-owner6@example.com", username="ws_owner6")
    editor = register_user(email="ws-editor6@example.com", username="ws_editor6")
    stranger = register_user(email="ws-stranger6@example.com", username="ws_stranger6")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])
    stranger_h = auth_header(stranger["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "ws-editor6@example.com"}, headers=owner_h)
    client.put(f"/api/origins/{origin_id}", json={"label": "renamed-for-audit-view"}, headers=owner_h)

    resp = client.get(f"/api/origins/{origin_id}/audit-log", headers=owner_h)
    assert resp.status_code == 200, resp.text
    events = resp.json()["events"]
    assert any(e["action"] == "origin.update" for e in events)
    assert any(e["action"] == "editor.grant" for e in events)

    resp = client.get(f"/api/origins/{origin_id}/audit-log", headers=editor_h)
    assert resp.status_code == 200, resp.text

    resp = client.get(f"/api/origins/{origin_id}/audit-log", headers=stranger_h)
    assert resp.status_code == 403
