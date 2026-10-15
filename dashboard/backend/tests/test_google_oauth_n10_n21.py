"""N10: Google sign-in must not take over an existing account by email.
N21: the callback must finish a flow started in this browser (state), with
PKCE and a nonce; a forged or missing state is refused."""
import uuid
from urllib.parse import parse_qs, urlparse

import pytest

import api.auth as auth_api
from services.auth_service import AuthService, GoogleLoginRejected

svc = AuthService()


def _new(register_user):
    tag = uuid.uuid4().hex[:8]
    return register_user(f"local-{tag}@example.com", f"local{tag}")


def _google(sub=None, email=None, verified=True):
    return {"sub": sub or f"g-{uuid.uuid4().hex}", "email": email or f"{uuid.uuid4().hex[:8]}@example.com",
            "email_verified": verified, "name": "G User", "picture": ""}


# ------------------------------------------------------------------ N10
def test_unverified_google_email_is_rejected():
    with pytest.raises(GoogleLoginRejected, match="google_email_unverified"):
        svc.login_or_register_google(_google(verified=False))


def test_email_verified_must_be_true_not_truthy_string():
    with pytest.raises(GoogleLoginRejected):
        svc.login_or_register_google(_google(verified="true"))


def test_email_match_does_not_sign_into_existing_password_account(register_user):
    body = _new(register_user)
    with pytest.raises(GoogleLoginRejected, match="google_link_required"):
        svc.login_or_register_google(_google(email=body["user"]["email"]))


def test_new_google_user_is_created_and_signs_in_again():
    g = _google()
    first = svc.login_or_register_google(g)
    again = svc.login_or_register_google(g)
    assert first["user_id"] == again["user_id"]
    assert first["role"] != "admin"


def test_signed_in_user_can_link_google_then_use_it(register_user):
    body = _new(register_user)
    me = svc.get_user_by_id(body["user"]["user_id"])
    g = _google(email=me["email"])
    linked = svc.login_or_register_google(g, link_to=me)
    assert linked["user_id"] == me["user_id"]
    assert svc.login_or_register_google(g)["user_id"] == me["user_id"]


def test_google_identity_linked_elsewhere_cannot_be_relinked(register_user):
    g = _google()
    owner = svc.login_or_register_google(g)
    other = svc.get_user_by_id(_new(register_user)["user"]["user_id"])
    with pytest.raises(GoogleLoginRejected, match="google_linked_elsewhere"):
        svc.login_or_register_google(g, link_to=other)
    assert svc.login_or_register_google(g)["user_id"] == owner["user_id"]


# ------------------------------------------------------------------ N21
def test_auth_url_carries_state_pkce_and_nonce():
    url, flow = svc.start_google_flow()
    q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    assert q["code_challenge_method"] == "S256" and q["code_challenge"] and q["nonce"] and q["state"]
    read = svc.read_google_flow(flow, q["state"])
    assert read and read["nonce"] == q["nonce"] and read["cv"]


def test_wrong_or_missing_state_is_refused():
    _, flow = svc.start_google_flow()
    assert svc.read_google_flow(flow, "not-the-state") is None
    assert svc.read_google_flow(flow, "") is None
    assert svc.read_google_flow(None, "x") is None


def test_flow_cookie_is_not_a_session_token():
    url, flow = svc.start_google_flow()
    assert svc.decode_token(flow) is None


def test_callback_without_flow_cookie_redirects_with_error(client, monkeypatch):
    called = []
    monkeypatch.setattr(auth_api.auth_service, "exchange_google_code", lambda *a: called.append(a))
    client.cookies.clear()
    r = client.get("/api/auth/google/callback?code=c&state=s", follow_redirects=False)
    assert r.status_code == 302 and "error=google_state" in r.headers["location"]
    assert called == []  # the code is never exchanged


def test_callback_completes_only_with_matching_state(client, monkeypatch):
    r = client.get("/api/auth/google", follow_redirects=False)
    assert r.status_code in (302, 307)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    g = _google()
    monkeypatch.setattr(auth_api.auth_service, "exchange_google_code", lambda code, cv, nonce: g)
    bad = client.get("/api/auth/google/callback?code=c&state=forged", follow_redirects=False)
    assert "error=google_state" in bad.headers["location"]
    # a refused callback also discards the flow, so start a new one
    r = client.get("/api/auth/google", follow_redirects=False)
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    ok = client.get(f"/api/auth/google/callback?code=c&state={state}", follow_redirects=False)
    assert ok.headers["location"] == "/oauth-success"
    assert client.get("/api/auth/me").status_code == 200


def test_link_requires_a_signed_in_session(client):
    client.cookies.clear()
    assert client.get("/api/auth/google?link=true", follow_redirects=False).status_code == 401

