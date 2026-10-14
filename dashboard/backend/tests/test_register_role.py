"""Self-registration never grants admin in production (owner's decision
2026-10-15): the first admin is seeded by an operator, so nobody can claim
the platform by being the first to sign up after a reset."""
import pytest

from api import auth as auth_module


@pytest.fixture()
def production_default(monkeypatch):
    monkeypatch.delenv("WAF_FIRST_USER_ADMIN", raising=False)


def _register(client, email, username, **extra):
    return client.post("/api/auth/register",
                       json={"email": email, "username": username, "password": "Sup3rSecret!", **extra})


def test_first_user_is_a_viewer_by_default(client, production_default):
    resp = _register(client, "first@example.com", "first")
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["role"] == "viewer"


def test_asking_for_admin_still_gives_viewer(client, production_default):
    resp = _register(client, "wants-admin@example.com", "wants_admin", role="admin")
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["role"] == "viewer"


def test_bootstrap_rule_only_when_explicitly_enabled(client, monkeypatch):
    monkeypatch.setenv("WAF_FIRST_USER_ADMIN", "true")
    assert _register(client, "boot@example.com", "boot").json()["user"]["role"] == "admin"
    assert _register(client, "second@example.com", "second").json()["user"]["role"] == "viewer"


@pytest.mark.parametrize("payload", [
    {"role": "editor"},          # not a platform role
    {"password": ""},            # local accounts need a password
])
def test_invalid_register_input_is_rejected_not_a_500(client, payload):
    body = {"email": "bad-input@example.com", "username": "bad_input", "password": "Sup3rSecret!", **payload}
    resp = client.post("/api/auth/register", json=body)
    assert resp.status_code == 422


def test_first_user_admin_flag_reads_env(monkeypatch):
    monkeypatch.setenv("WAF_FIRST_USER_ADMIN", "false")
    assert auth_module._first_user_admin_enabled() is False
    monkeypatch.setenv("WAF_FIRST_USER_ADMIN", "TRUE")
    assert auth_module._first_user_admin_enabled() is True
