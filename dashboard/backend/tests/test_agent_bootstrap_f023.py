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
    from tests.helpers.seed import make_tunnel_owner
    owner = make_tunnel_owner("myshop.com")  # P3.2: the token's holder owns the verified domain
    data = {"sub": owner, "user_id": owner, "domain": "myshop.com", "type": "tunnel_token"}
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


def test_token_of_a_deleted_user_or_archived_origin_gets_nothing(bootstrap_client):
    """P3.6 (N20): the token itself is still unexpired, but its holder or its
    domain's origin is gone."""
    from services.dynamodb_service import DynamoDBService
    token = _tunnel_token()
    db = DynamoDBService()
    origin_id = db.get_verified_domain("myshop.com")["origin_id"]
    db.delete_origin(origin_id)
    assert _get(bootstrap_client, token).status_code == 401
    db.restore_origin(origin_id)
    assert _get(bootstrap_client, token).status_code == 200
    owner = db.get_origin_by_id(origin_id)["admin_user_id"]
    from services.pg_store import PgUserRepository
    PgUserRepository().delete(owner)
    assert _get(bootstrap_client, token).status_code == 401


def test_token_for_an_unverified_or_foreign_domain_gets_nothing(bootstrap_client):
    from tests.helpers.seed import ensure_user, make_domain, make_origin, uid
    stranger = ensure_user(uid("stranger"))
    origin = make_origin({"user_id": stranger})
    make_domain(origin, "pending.example.com", dns_verified=False)
    pending = tunnels.auth_service.create_access_token(
        {"sub": stranger, "user_id": stranger, "domain": "pending.example.com", "type": "tunnel_token"},
        expires_delta=timedelta(days=1))
    assert _get(bootstrap_client, pending).status_code == 401
    _tunnel_token()  # myshop.com belongs to its own owner
    foreign = tunnels.auth_service.create_access_token(
        {"sub": stranger, "user_id": stranger, "domain": "myshop.com", "type": "tunnel_token"},
        expires_delta=timedelta(days=1))
    assert _get(bootstrap_client, foreign).status_code == 401
