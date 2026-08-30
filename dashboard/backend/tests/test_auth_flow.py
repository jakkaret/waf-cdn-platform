"""
Scenario: auth: register -> login -> /api/auth/me

This is the path everything else in the suite depends on: if a user cannot
register, log in, and be recognised by services/rbac.get_current_user, no
other scenario (RBAC, tenant isolation, rules CRUD) can be exercised either.
"""
from fastapi.testclient import TestClient


def test_register_login_me_round_trip(client: TestClient, register_user, auth_header,
                                       default_password):
    # Register: the very first user against a fresh store auto-promotes to admin.
    reg = register_user(email="alice@example.com", username="alice")
    assert reg["user"]["role"] == "admin"
    assert reg["user"]["email"] == "alice@example.com"
    assert "access_token" in reg

    # Login with the same credentials issues a fresh, independently valid token.
    login_resp = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": default_password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    assert token

    # /api/auth/me must recognise the freshly-issued login token.
    me_resp = client.get("/api/auth/me", headers=auth_header(token))
    assert me_resp.status_code == 200
    me_body = me_resp.json()
    assert me_body["email"] == "alice@example.com"
    assert me_body["username"] == "alice"
    assert me_body["role"] == "admin"


def test_me_rejects_missing_token(client: TestClient):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_login_rejects_wrong_password(client: TestClient, register_user):
    register_user(email="bob@example.com", username="bob")
    resp = client.post(
        "/api/auth/login",
        json={"email": "bob@example.com", "password": "not-the-right-password"},
    )
    assert resp.status_code == 401
