"""Email verification by a 6-digit code, the features it unlocks, and password
reset (which signs the account out everywhere).

An account exists right after sign-up but cannot add a site, invite or join a
team, mint agent tokens or use the AI features until the emailed code is
confirmed (services/rbac.py require_verified_email)."""
import pytest

from db import pool
from services import email_codes, mailer

pytestmark = pytest.mark.email_unverified

NEW_PASSWORD = "N3w-Passw0rd!"


def _codes(mailbox, purpose):
    return [m["code"] for m in mailbox if m["purpose"] == purpose]


def _signup(register_user, auth_header, email="owner@example.com", username="owner"):
    register_user(email="bootstrap@example.com", username="bootstrap")  # first account becomes admin
    body = register_user(email=email, username=username)
    return body, auth_header(body["access_token"])


def _age_code(user_id, purpose, seconds):
    pool.exec_("UPDATE email_codes SET created_at = created_at - make_interval(secs => %s) "
               "WHERE user_id = %s AND purpose = %s", (seconds, user_id, purpose))


def test_signup_leaves_the_account_unverified_and_mails_a_code(client, register_user, auth_header, code_mailbox):
    body, headers = _signup(register_user, auth_header)
    assert body["user"]["email_verified"] is False
    assert client.get("/api/auth/me", headers=headers).json()["email_verified"] is False
    codes = [m for m in code_mailbox if m["to"] == "owner@example.com"]
    assert len(codes) == 1 and codes[0]["purpose"] == "verify"
    assert len(codes[0]["code"]) == 6 and codes[0]["code"].isdigit()


def test_unverified_account_cannot_add_a_site_or_accept_an_invitation(client, register_user, auth_header):
    _body, headers = _signup(register_user, auth_header)

    resp = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.10", "port": 80}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "email_unverified"
    assert resp.json()["detail"]["action"] == "create_origin"

    resp = client.post("/api/invites/accept", json={"token": "anything"}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["action"] == "accept_invite"

    # Looking around still works.
    assert client.get("/api/origins", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 200


def test_the_emailed_code_verifies_the_address_and_unlocks_sites(client, register_user, auth_header, code_mailbox):
    body, headers = _signup(register_user, auth_header)
    code = _codes(code_mailbox, "verify")[-1]

    wrong = "000000" if code != "000000" else "111111"
    assert client.post("/api/auth/verify-email/confirm", json={"code": wrong}, headers=headers).status_code == 400

    resp = client.post("/api/auth/verify-email/confirm", json={"code": code}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["email_verified"] is True
    # single use: the same code does not work twice, but a verified account just stays verified
    assert client.post("/api/auth/verify-email/confirm", json={"code": code}, headers=headers).status_code == 200

    resp = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.10", "port": 80}, headers=headers)
    assert resp.status_code == 200, resp.text


def test_a_verified_owner_can_invite_but_an_unverified_one_cannot(client, register_user, auth_header, code_mailbox):
    body, headers = _signup(register_user, auth_header)
    client.post("/api/auth/verify-email/confirm", json={"code": _codes(code_mailbox, "verify")[-1]}, headers=headers)
    origin_id = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.11", "port": 80},
                            headers=headers).json()["id"]
    assert client.post(f"/api/origins/{origin_id}/editors", json={"email": "mate@example.com"},
                       headers=headers).status_code == 200

    # The same owner, if the address were not verified, is refused.
    pool.exec_("UPDATE users SET email_verified_at = NULL WHERE user_id = %s", (body["user"]["user_id"],))
    resp = client.post(f"/api/origins/{origin_id}/viewers", json={"email": "other@example.com"}, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["action"] == "invite"


def test_resend_waits_for_the_cooldown_and_a_new_code_replaces_the_old(client, register_user, auth_header, code_mailbox):
    body, headers = _signup(register_user, auth_header)
    first = _codes(code_mailbox, "verify")[-1]

    resp = client.post("/api/auth/verify-email/send", headers=headers).json()
    assert resp["sent"] is False and 0 < resp["retry_after"] <= email_codes.RESEND_COOLDOWN_SECONDS

    _age_code(body["user"]["user_id"], "verify", email_codes.RESEND_COOLDOWN_SECONDS + 1)
    resp = client.post("/api/auth/verify-email/send", headers=headers).json()
    assert resp["sent"] is True
    second = _codes(code_mailbox, "verify")[-1]
    if second != first:
        assert client.post("/api/auth/verify-email/confirm", json={"code": first}, headers=headers).status_code == 400
    assert client.post("/api/auth/verify-email/confirm", json={"code": second}, headers=headers).status_code == 200


def test_a_code_dies_after_too_many_wrong_guesses(client, register_user, auth_header, code_mailbox):
    _body, headers = _signup(register_user, auth_header)
    code = _codes(code_mailbox, "verify")[-1]
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(email_codes.MAX_ATTEMPTS):
        client.post("/api/auth/verify-email/confirm", json={"code": wrong}, headers=headers)
    assert client.post("/api/auth/verify-email/confirm", json={"code": code}, headers=headers).status_code == 400


def test_an_expired_code_is_refused(client, register_user, auth_header, code_mailbox):
    body, headers = _signup(register_user, auth_header)
    code = _codes(code_mailbox, "verify")[-1]
    pool.exec_("UPDATE email_codes SET expires_at = now() - interval '1 second' WHERE user_id = %s",
               (body["user"]["user_id"],))
    assert client.post("/api/auth/verify-email/confirm", json={"code": code}, headers=headers).status_code == 400


def test_hourly_cap_on_codes(register_user, auth_header):
    body, _headers = _signup(register_user, auth_header)
    uid = body["user"]["user_id"]
    for _ in range(email_codes.HOURLY_SENDS - 1):
        _age_code(uid, "verify", email_codes.RESEND_COOLDOWN_SECONDS + 1)
        assert email_codes.issue(uid, "verify")[0] is not None
    _age_code(uid, "verify", email_codes.RESEND_COOLDOWN_SECONDS + 1)
    code, wait = email_codes.issue(uid, "verify")
    assert code is None and wait > 0


def test_forgot_password_answers_the_same_for_unknown_addresses(client, register_user, auth_header, code_mailbox):
    _signup(register_user, auth_header)
    known = client.post("/api/auth/password/forgot", json={"email": "owner@example.com"})
    unknown = client.post("/api/auth/password/forgot", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()
    assert [m["to"] for m in code_mailbox if m["purpose"] == "reset"] == ["owner@example.com"]


def test_password_reset_signs_out_every_session_and_verifies_the_address(client, register_user, auth_header, code_mailbox):
    """Pre-hijacking: someone registered this address first. The mailbox
    owner resets the password, takes the account over, and the earlier
    sessions die."""
    body, squatter = _signup(register_user, auth_header)
    assert client.get("/api/auth/me", headers=squatter).status_code == 200

    client.post("/api/auth/password/forgot", json={"email": "owner@example.com"})
    code = _codes(code_mailbox, "reset")[-1]

    weak = client.post("/api/auth/password/reset", json={"email": "owner@example.com", "code": code, "new_password": "password1"})
    assert weak.status_code == 400
    bad = client.post("/api/auth/password/reset",
                      json={"email": "owner@example.com", "code": "999999" if code != "999999" else "888888",
                            "new_password": NEW_PASSWORD})
    assert bad.status_code == 400

    resp = client.post("/api/auth/password/reset",
                       json={"email": "owner@example.com", "code": code, "new_password": NEW_PASSWORD})
    assert resp.status_code == 200, resp.text

    client.cookies.clear()
    assert client.get("/api/auth/me", headers=squatter).status_code == 401
    assert client.post("/api/auth/login", json={"email": "owner@example.com", "password": "Sup3rSecret!"}).status_code == 401
    login = client.post("/api/auth/login", json={"email": "owner@example.com", "password": NEW_PASSWORD})
    assert login.status_code == 200
    assert login.json()["user"]["email_verified"] is True
    # the code was single use
    again = client.post("/api/auth/password/reset",
                        json={"email": "owner@example.com", "code": code, "new_password": NEW_PASSWORD})
    assert again.status_code == 400


def test_google_accounts_get_no_reset_code(client, code_mailbox):
    from services.auth_service import AuthService
    AuthService().create_user(email="g@example.com", username="g", auth_provider="google",
                              provider_id="g-123", email_verified=True)
    resp = client.post("/api/auth/password/forgot", json={"email": "g@example.com"})
    assert resp.status_code == 200
    assert not [m for m in code_mailbox if m["purpose"] == "reset"]


def test_reserved_domains_never_get_mail(monkeypatch):
    for addr in ("pgmig-1@example.org", "a@example.com", "x@shop.example.net", "q@host.test", "z@a.invalid"):
        assert mailer.deliverable(addr) is False, addr
    assert mailer.deliverable("someone@gmail.com") is True
    monkeypatch.setenv("SMTP_HOST", "smtp.invalid")
    assert mailer.send_mail("pgmig-1@example.org", "s", "t") is False
