"""Phase 3 (users, origins, domains on PostgreSQL): API-level behaviour the
migration must keep or newly guarantee."""
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

PG_MODE = os.environ.get("DATA_BACKEND", "").strip().lower() == "postgres"
pg_only = pytest.mark.skipif(not PG_MODE, reason="PostgreSQL-only guarantee (DATA_BACKEND=postgres)")


@pytest.fixture()
def full_client(app: FastAPI) -> TestClient:
    from api import domains as domains_module
    from api import tunnel as tunnel_module
    app.include_router(domains_module.origins_domains_router)
    app.include_router(tunnel_module.router)
    return TestClient(app)


def _setup(full_client, register_user, auth_header, creator="owner"):
    admin = register_user(email="p3-admin@example.com", username="p3_admin")  # first = admin (test env)
    owner = register_user(email="p3-owner@example.com", username="p3_owner")
    viewer = register_user(email="p3-viewer@example.com", username="p3_viewer")
    h = {k: auth_header(v["access_token"]) for k, v in
         {"admin": admin, "owner": owner, "viewer": viewer}.items()}
    origin_id = full_client.post("/api/origins", json={"label": "P3", "ip": "203.0.113.70", "port": 80},
                                 headers=h[creator]).json()["id"]
    return admin, owner, viewer, h, origin_id


def test_duplicate_domain_is_a_400_with_the_same_message(full_client, register_user, auth_header):
    _admin, _owner, _viewer, h, origin_id = _setup(full_client, register_user, auth_header)
    url = f"/api/origins/{origin_id}/domains"
    assert full_client.post(url, json={"domain_name": "p3-shop.example.org"}, headers=h["owner"]).status_code == 200
    resp = full_client.post(url, json={"domain_name": "p3-shop.example.org"}, headers=h["owner"])
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Domain name p3-shop.example.org is already registered."


@pg_only
def test_viewer_never_sees_the_tunnel_token_hash(full_client, register_user, auth_header):
    # Issuing an agent token needs a platform admin who owns the origin.
    _admin, _owner, viewer, h, origin_id = _setup(full_client, register_user, auth_header, creator="admin")
    assert full_client.post(f"/api/origins/{origin_id}/viewers", json={"email": "p3-viewer@example.com"},
                            headers=h["admin"]).status_code == 200
    issued = full_client.post("/api/tunnel/issue-token",
                              json={"origin_id": origin_id, "domains": ["p3-tunnel.example.org"]},
                              headers=h["admin"])
    assert issued.status_code == 200, issued.text
    for path in (f"/api/origins/{origin_id}", "/api/origins"):
        body = full_client.get(path, headers=h["viewer"]).json()
        assert "tunnel_token_hash" not in str(body)
    # the agent credential still verifies through its own path
    token = issued.json()["token"]
    ok = full_client.post("/api/tunnel/verify-agent", json={"token": token, "domains": ["p3-tunnel.example.org"]})
    assert ok.status_code == 200, ok.text


@pg_only
def test_a_tunnel_host_claimed_by_another_origin_is_a_409(full_client, register_user, auth_header):
    _admin, _owner, _viewer, h, origin_a = _setup(full_client, register_user, auth_header, creator="admin")
    origin_b = full_client.post("/api/origins", json={"label": "P3b", "ip": "203.0.113.71", "port": 80},
                                headers=h["admin"]).json()["id"]
    first = full_client.post("/api/tunnel/issue-token",
                             json={"origin_id": origin_a, "domains": ["p3-same.example.org"]}, headers=h["admin"])
    assert first.status_code == 200, first.text
    second = full_client.post("/api/tunnel/issue-token",
                              json={"origin_id": origin_b, "domains": ["p3-same.example.org"]}, headers=h["admin"])
    assert second.status_code == 409


@pg_only
def test_deleting_an_origin_owner_archives_their_origins(full_client, register_user, auth_header):
    _admin, owner, _viewer, h, origin_id = _setup(full_client, register_user, auth_header)
    resp = full_client.delete(f"/api/auth/users/{owner['user']['user_id']}", headers=h["admin"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["archived_origins"] == 1
    from services.dynamodb_service import DynamoDBService
    origin = DynamoDBService().get_origin_by_id(origin_id)
    assert origin["status"] == "archived" and origin["admin_user_id"] is None


def test_malformed_origin_id_is_a_404_not_a_500(full_client, register_user, auth_header):
    _admin, _owner, _viewer, h, _origin_id = _setup(full_client, register_user, auth_header)
    resp = full_client.get("/api/origins/not-a-uuid", headers=h["owner"])
    assert resp.status_code in (403, 404)
