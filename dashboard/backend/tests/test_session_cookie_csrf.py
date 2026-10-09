"""Session hardening (2026-10-09): auth rides an HttpOnly session cookie, a
companion csrf_token cookie backs double-submit CSRF, and cookie-authenticated
state-changing requests must carry a matching X-CSRF-Token."""
import os

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from api import auth as auth_module
from services.rbac import get_current_user


@pytest.fixture
def app_with_csrf():
    # Import the middleware from the real app module without starting its workers.
    from services.csrf import CSRFMiddleware
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)
    app.include_router(auth_module.router)

    @app.post("/api/echo")
    async def echo(user: dict = Depends(get_current_user)):
        return {"ok": True, "user": user.get("user_id")}

    return app


@pytest.fixture
def csrf_client(app_with_csrf, register_user):
    # register_user (conftest) seeds a user via the fake DynamoDB store.
    register_user(email="csrf@example.com", username="csrf_user", password="Str0ngPass!23")
    return TestClient(app_with_csrf)


def _login(client):
    r = client.post("/api/auth/login", json={"email": "csrf@example.com", "password": "Str0ngPass!23"})
    assert r.status_code == 200, r.text
    return r


def test_login_sets_httponly_session_and_readable_csrf_cookie(csrf_client):
    r = _login(csrf_client)
    jar = r.cookies
    assert "access_token" in jar and "csrf_token" in jar
    raw = r.headers.get("set-cookie", "")
    assert "access_token=" in raw and "HttpOnly" in raw  # session cookie is HttpOnly
    # the csrf cookie must be readable by JS -> NOT HttpOnly
    csrf_segment = [c for c in raw.split(", ") if c.strip().startswith("csrf_token=")]
    assert csrf_segment and "HttpOnly" not in csrf_segment[0]


def test_cookie_post_without_csrf_header_is_blocked(csrf_client):
    _login(csrf_client)
    # TestClient replays the session + csrf cookies, but no X-CSRF-Token header.
    r = csrf_client.post("/api/echo")
    assert r.status_code == 403
    assert "csrf" in r.json()["detail"].lower()


def test_cookie_post_with_matching_csrf_header_passes(csrf_client):
    _login(csrf_client)
    csrf = csrf_client.cookies.get("csrf_token")
    r = csrf_client.post("/api/echo", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["ok"] is True


def test_cookie_post_with_wrong_csrf_header_is_blocked(csrf_client):
    _login(csrf_client)
    r = csrf_client.post("/api/echo", headers={"X-CSRF-Token": "not-the-value"})
    assert r.status_code == 403


def test_bearer_auth_is_exempt_from_csrf(app_with_csrf, register_user):
    reg = register_user(email="bearer@example.com", username="bearer_user", password="Str0ngPass!23")
    token = reg["access_token"]
    # fresh client with no cookies; authenticate purely by Bearer
    c = TestClient(app_with_csrf)
    r = c.post("/api/echo", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["ok"] is True


def test_get_me_needs_no_csrf(csrf_client):
    _login(csrf_client)
    assert csrf_client.get("/api/auth/me").status_code == 200


def test_logout_clears_both_cookies(csrf_client):
    _login(csrf_client)
    csrf = csrf_client.cookies.get("csrf_token")
    r = csrf_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    raw = r.headers.get("set-cookie", "")
    assert "access_token=" in raw and "csrf_token=" in raw  # both deleted (expired)
