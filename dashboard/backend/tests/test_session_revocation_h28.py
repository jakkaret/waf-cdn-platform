"""H28/H31: logout must revoke the session on the server. A token copied
before logout (or before a role change) must stop working at once."""
import uuid

from services.auth_service import AuthService

svc = AuthService()


def _register(register_user):
    tag = uuid.uuid4().hex[:8]
    return register_user(f"rev-{tag}@example.com", f"rev{tag}")


def test_token_used_after_logout_is_rejected(client, register_user, auth_header):
    body = _register(register_user)
    token = body["access_token"]
    assert client.get("/api/auth/me", headers=auth_header(token)).status_code == 200
    assert client.post("/api/auth/logout", headers=auth_header(token)).status_code == 200
    r = client.get("/api/auth/me", headers=auth_header(token))
    assert r.status_code == 401 and r.json()["detail"] == "Session revoked"


def test_logout_with_bearer_header_only_revokes(client, register_user, auth_header):
    body = _register(register_user)
    token = body["access_token"]
    client.cookies.clear()  # header only, as API clients do
    assert client.post("/api/auth/logout", headers=auth_header(token)).status_code == 200
    assert client.get("/api/auth/me", headers=auth_header(token)).status_code == 401


def test_new_login_after_logout_works(client, register_user, auth_header):
    body = _register(register_user)
    client.post("/api/auth/logout", headers=auth_header(body["access_token"]))
    fresh = svc.create_access_token({"sub": body["user"]["user_id"], "role": "viewer", "email": body["user"]["email"]})
    assert client.get("/api/auth/me", headers=auth_header(fresh)).status_code == 200


def test_role_change_revokes_existing_sessions(client, register_user, auth_header):
    body = _register(register_user)
    token = body["access_token"]
    svc.update_user_role(body["user"]["user_id"], "viewer")
    assert client.get("/api/auth/me", headers=auth_header(token)).status_code == 401


def test_deleted_user_token_is_rejected(client, register_user, auth_header):
    body = _register(register_user)
    svc.delete_user(body["user"]["user_id"])
    assert client.get("/api/auth/me", headers=auth_header(body["access_token"])).status_code == 401


def test_logout_without_session_still_clears_cookies(client):
    client.cookies.clear()
    assert client.post("/api/auth/logout").status_code == 200


def test_session_token_carries_version_and_tunnel_token_does_not(register_user):
    body = _register(register_user)
    payload = svc.decode_token(body["access_token"])
    assert payload["tv"] == 0
    tunnel = svc.create_access_token({"sub": body["user"]["user_id"], "type": "tunnel_token"})
    assert "tv" not in svc.decode_token(tunnel)
