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


# ---- signed-in devices page
def _login_ua(client, email, ua):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}, headers={"User-Agent": ua})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_device_list_shows_each_session_and_marks_this_one(client, register_user, auth_header):
    email = _account(register_user)
    phone = _login_ua(client, email, "Mozilla/5.0 (iPhone) Safari")
    laptop = _login_ua(client, email, "Mozilla/5.0 (Macintosh) Chrome/130")
    client.cookies.clear()
    r = client.get("/api/auth/sessions", headers=auth_header(laptop))
    assert r.status_code == 200
    rows = [s for s in r.json()["sessions"] if s["user_agent"] != "testclient"]  # registration's own session
    assert {s["user_agent"] for s in rows} == {"Mozilla/5.0 (iPhone) Safari", "Mozilla/5.0 (Macintosh) Chrome/130"}
    current = [s for s in rows if s["current"]]
    assert len(current) == 1 and current[0]["session_id"] == svc.decode_token(laptop)["sid"]


def test_signing_out_one_other_device(client, register_user, auth_header):
    email = _account(register_user)
    phone = _login_ua(client, email, "phone")
    laptop = _login_ua(client, email, "laptop")
    client.cookies.clear()
    r = client.delete(f"/api/auth/sessions/{svc.decode_token(phone)['sid']}", headers=auth_header(laptop))
    assert r.status_code == 200 and r.json() == {"status": "revoked", "current": False}
    assert _me(client, phone, auth_header) == 401
    assert _me(client, laptop, auth_header) == 200
    client.cookies.clear()
    left = client.get("/api/auth/sessions", headers=auth_header(laptop)).json()["sessions"]
    assert [s["user_agent"] for s in left if s["user_agent"] != "testclient"] == ["laptop"]


def test_signing_out_this_device_from_the_list(client, register_user, auth_header):
    email = _account(register_user)
    laptop = _login_ua(client, email, "laptop")
    client.cookies.clear()
    r = client.delete(f"/api/auth/sessions/{svc.decode_token(laptop)['sid']}", headers=auth_header(laptop))
    assert r.status_code == 200 and r.json()["current"] is True
    assert _me(client, laptop, auth_header) == 401


def test_cannot_list_or_revoke_someone_elses_sessions(client, register_user, auth_header):
    mine = _login_ua(client, _account(register_user), "mine")
    theirs = _login_ua(client, _account(register_user), "theirs")
    client.cookies.clear()
    assert all(s["user_agent"] != "theirs" for s in client.get("/api/auth/sessions", headers=auth_header(mine)).json()["sessions"])
    r = client.delete(f"/api/auth/sessions/{svc.decode_token(theirs)['sid']}", headers=auth_header(mine))
    assert r.status_code == 404
    assert _me(client, theirs, auth_header) == 200


def test_revoked_and_unknown_sessions_are_404(client, register_user, auth_header):
    email = _account(register_user)
    a = _login_ua(client, email, "a")
    b = _login_ua(client, email, "b")
    client.cookies.clear()
    sid_a = svc.decode_token(a)["sid"]
    assert client.delete(f"/api/auth/sessions/{sid_a}", headers=auth_header(b)).status_code == 200
    assert client.delete(f"/api/auth/sessions/{sid_a}", headers=auth_header(b)).status_code == 404
    assert client.delete("/api/auth/sessions/not-a-uuid", headers=auth_header(b)).status_code == 404


def test_session_endpoints_need_a_session(client):
    client.cookies.clear()
    assert client.get("/api/auth/sessions").status_code == 401
    assert client.delete(f"/api/auth/sessions/{uuid.uuid4()}").status_code == 401
