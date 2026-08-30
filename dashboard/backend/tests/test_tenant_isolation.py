"""
Scenario: tenant isolation - user A cannot read user B's origin.

Protects services/rbac.verify_origin_ownership from a query edit that
crosses tenants. Exercises the real create_origin -> get_origin_by_id path
through services/origin_service.py and services/dynamodb_service.py (against
the fake table), not a hand-rolled shortcut.
"""
from fastapi.testclient import TestClient


def _create_origin(client, token, auth_header, label="edge-1"):
    resp = client.post(
        "/api/origins",
        json={"label": label, "ip": "203.0.113.10", "port": 8080},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_user_b_cannot_read_user_a_origin(client: TestClient, register_user, auth_header):
    user_a = register_user(email="tenant-a@example.com", username="tenant_a")
    user_b = register_user(email="tenant-b@example.com", username="tenant_b", role="viewer")

    origin = _create_origin(client, user_a["access_token"], auth_header)
    origin_id = origin["origin_id"]

    # Owner can read their own origin.
    own_resp = client.get(f"/api/origins/{origin_id}", headers=auth_header(user_a["access_token"]))
    assert own_resp.status_code == 200
    assert own_resp.json()["origin_id"] == origin_id

    # A different tenant must be refused, not silently shown someone else's origin.
    cross_resp = client.get(f"/api/origins/{origin_id}", headers=auth_header(user_b["access_token"]))
    assert cross_resp.status_code == 403


def test_user_b_cannot_delete_user_a_origin(client: TestClient, register_user, auth_header):
    user_a = register_user(email="tenant-c@example.com", username="tenant_c")
    user_b = register_user(email="tenant-d@example.com", username="tenant_d", role="viewer")

    origin = _create_origin(client, user_a["access_token"], auth_header, label="edge-2")
    origin_id = origin["origin_id"]

    del_resp = client.delete(f"/api/origins/{origin_id}", headers=auth_header(user_b["access_token"]))
    assert del_resp.status_code == 403

    # Confirm it was not deleted: the owner can still see it.
    still_there = client.get(f"/api/origins/{origin_id}", headers=auth_header(user_a["access_token"]))
    assert still_there.status_code == 200


def test_user_b_origin_list_does_not_include_user_a_origin(client: TestClient, register_user,
                                                             auth_header):
    user_a = register_user(email="tenant-e@example.com", username="tenant_e")
    user_b = register_user(email="tenant-f@example.com", username="tenant_f", role="viewer")

    _create_origin(client, user_a["access_token"], auth_header, label="edge-3")

    listing = client.get("/api/origins", headers=auth_header(user_b["access_token"]))
    assert listing.status_code == 200
    assert listing.json()["origins"] == []
