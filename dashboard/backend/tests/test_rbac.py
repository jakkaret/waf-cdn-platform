"""
Scenario: RBAC - a `viewer` gets 403 on an admin-only endpoint.

Protects against a dependency edit (services/rbac.require_admin) accidentally
leaking privilege to viewers. Uses POST /api/rules/ (Depends(require_admin))
as the admin-only endpoint, and PUT /api/auth/users/{id}/role as a second,
independent admin-only endpoint for good measure.
"""
from fastapi.testclient import TestClient


def test_viewer_forbidden_from_admin_only_rule_creation(client: TestClient, register_user,
                                                          auth_header):
    # First registration always becomes admin; keep it around only to avoid
    # relying on registration order elsewhere.
    register_user(email="owner@example.com", username="owner")
    viewer = register_user(email="viewer@example.com", username="viewer1", role="viewer")
    assert viewer["user"]["role"] == "viewer"

    resp = client.post(
        "/api/rules/",
        json={
            "id": "9999",
            "variable": "REQUEST_URI",
            "operator": "@rx forbidden-test",
            "severity": "HIGH",
            "message": "should never be created",
        },
        headers=auth_header(viewer["access_token"]),
    )
    assert resp.status_code == 403


def test_viewer_forbidden_from_admin_only_role_update(client: TestClient, register_user,
                                                        auth_header):
    admin = register_user(email="root@example.com", username="root")
    viewer = register_user(email="viewer2@example.com", username="viewer2", role="viewer")

    resp = client.put(
        f"/api/auth/users/{admin['user']['user_id']}/role",
        json={"role": "viewer"},
        headers=auth_header(viewer["access_token"]),
    )
    assert resp.status_code == 403


def test_admin_can_create_rule(client: TestClient, register_user, auth_header):
    admin = register_user(email="admin-ok@example.com", username="admin_ok")
    resp = client.post(
        "/api/rules/",
        json={
            "id": "9998",
            "variable": "REQUEST_URI",
            "operator": "@rx allowed-test",
            "severity": "HIGH",
            "message": "created by an admin",
        },
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
