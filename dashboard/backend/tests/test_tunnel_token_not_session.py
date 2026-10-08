"""F-021: tunnel JWTs must not authenticate dashboard sessions; logout clears cookie."""
from datetime import timedelta

from services.auth_service import AuthService


def _tunnel_token(user):
    return AuthService().create_access_token(
        {"sub": user["user_id"], "user_id": user["user_id"], "domain": "x.example.com", "type": "tunnel_token"},
        expires_delta=timedelta(days=365),
    )


def test_tunnel_token_rejected_as_bearer(client, register_user):
    body = register_user(email="tt1@example.com", username="tt1")
    t = _tunnel_token(body["user"])
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 401


def test_tunnel_token_rejected_as_cookie(client, register_user):
    body = register_user(email="tt2@example.com", username="tt2")
    client.cookies.clear()
    client.cookies.set("access_token", _tunnel_token(body["user"]))
    assert client.get("/api/auth/me").status_code == 401


def test_session_token_still_works(client, register_user, auth_header):
    body = register_user(email="tt3@example.com", username="tt3")
    assert client.get("/api/auth/me", headers=auth_header(body["access_token"])).status_code == 200


def test_tunnel_token_still_decodes_for_tunnel_hook(register_user, client):
    body = register_user(email="tt4@example.com", username="tt4")
    payload = AuthService().decode_token(_tunnel_token(body["user"]))
    assert payload and payload["type"] == "tunnel_token"


def test_logout_deletes_access_cookie(client, register_user):
    register_user(email="tt5@example.com", username="tt5")
    assert client.cookies.get("access_token")
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "access_token=" in set_cookie and ("Max-Age=0" in set_cookie or "expires=" in set_cookie.lower())
    assert client.get("/api/auth/me").status_code == 401
