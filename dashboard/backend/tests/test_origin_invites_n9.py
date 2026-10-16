"""N9/H64: sharing an origin needs the mailbox, not just an account that was
registered under the address first."""
import pytest

from db import pool

pytestmark = pytest.mark.no_auto_accept


def _origin(client, h):
    r = client.post("/api/origins", json={"label": "inv-site", "ip": "203.0.113.70", "port": 8080}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


@pytest.fixture
def setup(client, register_user, auth_header):
    owner = register_user(email="inv-owner@example.com", username="invowner")
    squatter = register_user(email="victim@example.com", username="squatter")  # registered first, no mailbox
    real = register_user(email="real-person@example.com", username="realperson")
    h = {k: auth_header(v["access_token"]) for k, v in (("owner", owner), ("squatter", squatter), ("real", real))}
    return h, _origin(client, h["owner"])


def test_account_holding_the_email_gets_no_access_from_the_invite(client, setup, invite_mailbox):
    h, origin_id = setup
    r = client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"}, headers=h["owner"])
    assert r.json()["status"] == "invited"
    assert client.get(f"/api/origins/{origin_id}", headers=h["squatter"]).status_code in (403, 404)
    assert [m["to"] for m in invite_mailbox] == ["victim@example.com"]


def test_whoever_opens_the_emailed_link_gets_the_role(client, setup, invite_mailbox):
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "victim@example.com"}, headers=h["owner"])
    token = invite_mailbox[0]["token"]
    r = client.post("/api/invites/accept", json={"token": token}, headers=h["real"])
    assert r.status_code == 200 and r.json()["role"] == "editor"
    assert client.get(f"/api/origins/{origin_id}", headers=h["real"]).status_code == 200
    assert client.get(f"/api/origins/{origin_id}", headers=h["squatter"]).status_code in (403, 404)


def test_link_works_once(client, setup, invite_mailbox):
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"}, headers=h["owner"])
    token = invite_mailbox[0]["token"]
    assert client.post("/api/invites/accept", json={"token": token}, headers=h["real"]).status_code == 200
    assert client.post("/api/invites/accept", json={"token": token}, headers=h["squatter"]).status_code == 404


def test_expired_or_wrong_link_is_refused(client, setup, invite_mailbox):
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"}, headers=h["owner"])
    pool.exec_("UPDATE origin_invites SET expires_at = now() - interval '1 minute'")
    assert client.post("/api/invites/accept", json={"token": invite_mailbox[0]["token"]}, headers=h["real"]).status_code == 404
    assert client.post("/api/invites/accept", json={"token": "made-up"}, headers=h["real"]).status_code == 404


def test_accept_needs_a_session(client, setup, invite_mailbox):
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"}, headers=h["owner"])
    client.cookies.clear()
    assert client.post("/api/invites/accept", json={"token": invite_mailbox[0]["token"]}).status_code == 401


def test_only_the_token_hash_is_stored(client, setup, invite_mailbox):
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"}, headers=h["owner"])
    stored = pool.q1("SELECT token_hash FROM origin_invites")["token_hash"]
    assert invite_mailbox[0]["token"] not in stored and len(stored) == 64


def test_invite_link_ignores_a_spoofed_host_header(client, setup, invite_mailbox, monkeypatch):
    monkeypatch.setenv("PUBLIC_APP_URL", "https://waf-it-kku.online")
    h, origin_id = setup
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "victim@example.com"},
                headers={**h["owner"], "Host": "evil.example"})
    assert invite_mailbox[0]["link"].startswith("https://waf-it-kku.online/invites/accept?token=")
