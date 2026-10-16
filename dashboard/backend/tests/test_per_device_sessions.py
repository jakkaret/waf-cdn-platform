"""Per-device sessions (migration 0008): logout on one device leaves the
account's other devices signed in; "sign out of all devices", role changes
and account deletion still end every session."""
import uuid

from services.auth_service import AuthService
from services.pg_store import PgUserRepository

svc = AuthService()
PASSWORD = "Sup3rSecret!"


def _account(register_user):
    tag = uuid.uuid4().hex[:8]
    email = f"dev-{tag}@example.com"
    register_user(email, f"dev{tag}")
    return email


def _login(client, email):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _me(client, token, auth_header):
    client.cookies.clear()
    return client.get("/api/auth/me", headers=auth_header(token)).status_code


def test_every_sign_in_gets_its_own_session(client, register_user):
    email = _account(register_user)
    a, b = _login(client, email), _login(client, email)
    sa, sb = svc.decode_token(a)["sid"], svc.decode_token(b)["sid"]
    assert sa and sb and sa != sb


def test_logout_on_one_device_keeps_the_other(client, register_user, auth_header):
    email = _account(register_user)
    a, b = _login(client, email), _login(client, email)
    client.cookies.clear()
    assert client.post("/api/auth/logout", headers=auth_header(a)).status_code == 200
    assert _me(client, a, auth_header) == 401
    assert _me(client, b, auth_header) == 200


def test_logout_all_ends_every_device(client, register_user, auth_header):
    email = _account(register_user)
    a, b = _login(client, email), _login(client, email)
    client.cookies.clear()
    assert client.post("/api/auth/logout-all", headers=auth_header(a)).status_code == 200
    assert _me(client, a, auth_header) == 401
    assert _me(client, b, auth_header) == 401
    assert _me(client, _login(client, email), auth_header) == 200   # signing in again works


def test_role_change_ends_every_device(client, register_user, auth_header):
    email = _account(register_user)
    a, b = _login(client, email), _login(client, email)
    svc.update_user_role(svc.decode_token(a)["sub"], "viewer")
    assert _me(client, a, auth_header) == 401 and _me(client, b, auth_header) == 401


def test_deleted_account_ends_every_device(client, register_user, auth_header):
    email = _account(register_user)
    a = _login(client, email)
    svc.delete_user(svc.decode_token(a)["sub"])
    assert _me(client, a, auth_header) == 401


def test_revoked_or_expired_session_fails_even_with_a_valid_jwt(client, register_user, auth_header):
    from db import pool
    email = _account(register_user)
    a = _login(client, email)
    pool.exec_("UPDATE user_sessions SET expires_at = now() - interval '1 second' WHERE session_id = %s",
               (svc.decode_token(a)["sid"],))
    assert _me(client, a, auth_header) == 401


def test_session_of_another_user_is_not_accepted(client, register_user, auth_header):
    a_tok = _login(client, _account(register_user))
    b_tok = _login(client, _account(register_user))
    forged = svc.create_access_token({"sub": svc.decode_token(b_tok)["sub"], "role": "viewer",
                                      "sid": svc.decode_token(a_tok)["sid"]})
    assert _me(client, forged, auth_header) == 401


def test_token_without_sid_still_works_until_it_expires(client, register_user, auth_header):
    email = _account(register_user)
    a = _login(client, email)
    legacy = svc.create_access_token({"sub": svc.decode_token(a)["sub"], "role": "viewer", "email": email})
    assert "sid" not in svc.decode_token(legacy)
    assert _me(client, legacy, auth_header) == 200


def test_old_session_rows_are_purged_a_week_after_expiry(client, register_user):
    from db import pool
    email = _account(register_user)
    sid = svc.decode_token(_login(client, email))["sid"]
    pool.exec_("UPDATE user_sessions SET expires_at = now() - interval '8 days' WHERE session_id = %s", (sid,))
    assert PgUserRepository().purge_old_sessions(7) >= 1
    assert pool.q1("SELECT 1 AS x FROM user_sessions WHERE session_id = %s", (sid,)) is None
