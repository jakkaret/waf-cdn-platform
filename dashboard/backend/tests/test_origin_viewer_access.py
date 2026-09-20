"""
Scenario: 2026-09-19 added explicit viewer-grant to origins -- an owner can
share read-only access to a specific origin with another registered account
(services/rbac.verify_origin_access, api/origins.py's
GET/POST/DELETE /origins/{id}/viewers, services/origin_service.py's
get_origins_visible_to_user / list_origin_viewers, and
services/tenant_service.py's get_user_origins_and_domains extending scope to
granted origins). None of it had test coverage before this file.

Covers, end to end through the real HTTP routes (not calling the service
functions directly), exactly the invariants "owner grants, viewer reads-only,
nobody else sees it, revoke removes it" that the design intent (owner decides
who else can see it) rests on.
"""
from fastapi.testclient import TestClient


def _create_origin(client: TestClient, owner_headers: dict, label="Origin A", ip="10.0.0.1", port=8080) -> dict:
    resp = client.post("/api/origins", json={"label": label, "ip": ip, "port": port}, headers=owner_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_owner_can_read_and_manage_their_own_origin(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner@example.com", username="owner")
    headers = auth_header(owner["access_token"])
    origin = _create_origin(client, headers)

    resp = client.get(f"/api/origins/{origin['id']}", headers=headers)
    assert resp.status_code == 200

    resp = client.put(f"/api/origins/{origin['id']}", json={"label": "Renamed"}, headers=headers)
    assert resp.status_code == 200


def test_a_second_unrelated_account_sees_nothing_by_default(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner2@example.com", username="owner2")
    other = register_user(email="other@example.com", username="other")
    owner_headers = auth_header(owner["access_token"])
    other_headers = auth_header(other["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.2")

    assert client.get("/api/origins", headers=other_headers).json()["origins"] == []
    resp = client.get(f"/api/origins/{origin['id']}", headers=other_headers)
    assert resp.status_code == 403


def test_owner_grants_viewer_access_by_email(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner3@example.com", username="owner3")
    viewer = register_user(email="viewer3@example.com", username="viewer3")
    owner_headers = auth_header(owner["access_token"])
    viewer_headers = auth_header(viewer["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.3")

    resp = client.post(
        f"/api/origins/{origin['id']}/viewers",
        json={"email": "viewer3@example.com"},
        headers=owner_headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["viewer"]["email"] == "viewer3@example.com"

    # Viewer now sees it in their own list and can read it directly.
    listed = client.get("/api/origins", headers=viewer_headers).json()["origins"]
    assert [o["id"] for o in listed] == [origin["id"]]
    resp = client.get(f"/api/origins/{origin['id']}", headers=viewer_headers)
    assert resp.status_code == 200


def test_viewer_cannot_write_only_read(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner4@example.com", username="owner4")
    viewer = register_user(email="viewer4@example.com", username="viewer4")
    owner_headers = auth_header(owner["access_token"])
    viewer_headers = auth_header(viewer["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.4")
    client.post(f"/api/origins/{origin['id']}/viewers", json={"email": "viewer4@example.com"}, headers=owner_headers)

    resp = client.put(f"/api/origins/{origin['id']}", json={"label": "Hijacked"}, headers=viewer_headers)
    assert resp.status_code == 403

    resp = client.delete(f"/api/origins/{origin['id']}", headers=viewer_headers)
    assert resp.status_code == 403

    # A viewer is not an owner: they cannot grant further viewers either.
    resp = client.post(
        f"/api/origins/{origin['id']}/viewers",
        json={"email": "owner4@example.com"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_granting_a_nonexistent_email_is_rejected(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner5@example.com", username="owner5")
    owner_headers = auth_header(owner["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.5")

    resp = client.post(
        f"/api/origins/{origin['id']}/viewers",
        json={"email": "nobody-registered@example.com"},
        headers=owner_headers,
    )
    assert resp.status_code == 404


def test_granting_yourself_the_owner_is_rejected(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner6@example.com", username="owner6")
    owner_headers = auth_header(owner["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.6")

    resp = client.post(
        f"/api/origins/{origin['id']}/viewers",
        json={"email": "owner6@example.com"},
        headers=owner_headers,
    )
    assert resp.status_code == 400


def test_revoking_a_viewer_removes_their_access_immediately(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner7@example.com", username="owner7")
    viewer = register_user(email="viewer7@example.com", username="viewer7")
    owner_headers = auth_header(owner["access_token"])
    viewer_headers = auth_header(viewer["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.7")
    client.post(f"/api/origins/{origin['id']}/viewers", json={"email": "viewer7@example.com"}, headers=owner_headers)
    assert client.get(f"/api/origins/{origin['id']}", headers=viewer_headers).status_code == 200

    viewer_id = viewer["user"]["user_id"]
    resp = client.delete(f"/api/origins/{origin['id']}/viewers/{viewer_id}", headers=owner_headers)
    assert resp.status_code == 200

    assert client.get("/api/origins", headers=viewer_headers).json()["origins"] == []
    assert client.get(f"/api/origins/{origin['id']}", headers=viewer_headers).status_code == 403


def test_viewer_list_endpoint_is_owner_only(client: TestClient, register_user, auth_header):
    owner = register_user(email="owner8@example.com", username="owner8")
    viewer = register_user(email="viewer8@example.com", username="viewer8")
    owner_headers = auth_header(owner["access_token"])
    viewer_headers = auth_header(viewer["access_token"])
    origin = _create_origin(client, owner_headers, ip="10.0.0.8")
    client.post(f"/api/origins/{origin['id']}/viewers", json={"email": "viewer8@example.com"}, headers=owner_headers)

    resp = client.get(f"/api/origins/{origin['id']}/viewers", headers=owner_headers)
    assert resp.status_code == 200
    assert [v["email"] for v in resp.json()["viewers"]] == ["viewer8@example.com"]

    # The viewer themself cannot list who else has access -- that's an
    # owner-only management action, not something read access implies.
    resp = client.get(f"/api/origins/{origin['id']}/viewers", headers=viewer_headers)
    assert resp.status_code == 403
