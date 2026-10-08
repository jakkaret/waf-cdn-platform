"""F-023 regression: the public /install-agent.sh must not contain the frps
connection secret, and /api/tunnels/agent-bootstrap must release it only to a
holder of a valid, unexpired, domain-scoped tunnel token."""
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import tunnels

SECRET = "s3cr3t-frp-connection-value"


@pytest.fixture
def bootstrap_client(monkeypatch):
    monkeypatch.setattr(tunnels, "LEGACY_STATIC_TOKEN", SECRET)
    app = FastAPI()
    app.include_router(tunnels.router)
    return TestClient(app)


def _tunnel_token(**overrides):
    data = {"sub": "u1", "user_id": "u1", "domain": "myshop.com", "type": "tunnel_token"}
    data.update(overrides)
    return tunnels.auth_service.create_access_token(data, expires_delta=timedelta(days=1))


def _get(client, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.get("/api/tunnels/agent-bootstrap", headers=headers)


def test_install_script_contains_no_secret(monkeypatch):
    monkeypatch.setattr(tunnels, "LEGACY_STATIC_TOKEN", SECRET)
    body = tunnels.render_install_agent_script()
    assert SECRET not in body
    assert "/api/tunnels/agent-bootstrap" in body


def test_valid_tunnel_token_gets_the_secret(bootstrap_client):
    r = _get(bootstrap_client, _tunnel_token())
    assert r.status_code == 200
    assert r.text == SECRET


def test_session_token_is_rejected(bootstrap_client):
    session = tunnels.auth_service.create_access_token({"sub": "u1", "role": "admin"})
    assert _get(bootstrap_client, session).status_code == 401


def test_tunnel_token_without_domain_is_rejected(bootstrap_client):
    assert _get(bootstrap_client, _tunnel_token(domain="")).status_code == 401


def test_expired_tunnel_token_is_rejected(bootstrap_client):
    expired = tunnels.auth_service.create_access_token(
        {"sub": "u1", "domain": "myshop.com", "type": "tunnel_token"},
        expires_delta=timedelta(seconds=-10),
    )
    assert _get(bootstrap_client, expired).status_code == 401


@pytest.mark.parametrize("token", [None, "", "not-a-jwt"])
def test_missing_or_garbage_token_is_rejected(bootstrap_client, token):
    assert _get(bootstrap_client, token).status_code == 401


def test_unconfigured_secret_returns_503(bootstrap_client, monkeypatch):
    monkeypatch.setattr(tunnels, "LEGACY_STATIC_TOKEN", "")
    assert _get(bootstrap_client, _tunnel_token()).status_code == 503
