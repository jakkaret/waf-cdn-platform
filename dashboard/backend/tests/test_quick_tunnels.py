"""Quick tunnels (services/quick_tunnel.py, api/quick_tunnels.py): a user with
no domain gets a platform-named host under the quick tunnel zone, and the
existing tunnel paths (config-generator, the frps gatekeeper) serve it.

What must hold: the platform picks the name (F-129 stays closed), only the
owner (or an admin) can use or remove it, the limits apply, and an idle one
is removed.
"""
import re
from datetime import timedelta

import pytest
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import api.domains as domains_module
import api.quick_tunnels as quick_tunnels_module
import api.tunnels as tunnels_module
import services.origin_service as origin_service
from api import auth as auth_module
from api import origins as origins_module
from db import pool
from services import quick_tunnel
from services.auth_service import AuthService
from services.rate_limiter import limiter

NAME = re.compile(r"^t-[a-hj-km-np-z2-9]{8}\." + re.escape(quick_tunnel.ZONE) + "$")


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    test_app.include_router(tunnels_module.router)
    test_app.include_router(quick_tunnels_module.router)
    return test_app


class _AllowAll:
    def is_allowed(self, *a, **k):
        return True, 1, 0


@pytest.fixture(autouse=True)
def quiet_side_effects(monkeypatch):
    """No live frps, no managed-ruleset or nginx work, and a limiter that
    allows (fakeredis has no Lua; the limit itself has its own test)."""
    async def no_proxies(force=False):
        return []
    monkeypatch.setattr(origin_service, "get_live_proxies", no_proxies)
    monkeypatch.setattr(domains_module, "_refresh_managed_hostmap", lambda: None)
    monkeypatch.setattr(domains_module, "schedule_site_reconcile", lambda: None)
    monkeypatch.setattr(quick_tunnel, "_limiter", _AllowAll())


@pytest.fixture()
def people(register_user, auth_header):
    admin = register_user(email="qt-admin@example.com", username="qt_admin")  # first user = admin
    alice = register_user(email="qt-alice@example.com", username="qt_alice")
    bob = register_user(email="qt-bob@example.com", username="qt_bob")
    return {k: {"id": v["user"]["user_id"], "h": auth_header(v["access_token"])}
            for k, v in (("admin", admin), ("alice", alice), ("bob", bob))}


def _create(client, who, port=3000):
    resp = client.post("/api/tunnels/quick", json={"port": port}, headers=who["h"])
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_user_without_a_domain_gets_a_platform_name_and_an_agent_command(client, people):
    created = _create(client, people["alice"], port=8080)
    host = created["domain_name"]
    assert NAME.match(host), host
    assert created["url"] == f"https://{host}"

    resp = client.get("/api/tunnels/config-generator",
                      params={"domain": host, "port": 8080}, headers=people["alice"]["h"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert f"--domain {host} --port 8080" in body["linux_command"]
    assert f'customDomains = ["{host}"]' in body["toml_config"]

    listed = client.get("/api/tunnels/quick", headers=people["alice"]["h"]).json()
    assert [t["domain_name"] for t in listed["tunnels"]] == [host]
    assert listed["tunnels"][0]["port"] == 8080
    assert listed["tunnels"][0]["is_online"] is False
    assert listed["zone"] == quick_tunnel.ZONE


def test_the_name_is_never_taken_from_the_client(client, people):
    resp = client.post("/api/tunnels/quick", json={"port": 3000, "domain": f"paypal.{quick_tunnel.ZONE}"},
                       headers=people["alice"]["h"])
    assert resp.status_code == 422

    # Nor through the ordinary domain form on an origin the user owns.
    origin = client.post("/api/origins", json={"label": "site", "ip": "203.0.113.5", "port": 80},
                         headers=people["alice"]["h"])
    assert origin.status_code == 200, origin.text
    origin_id = origin.json().get("id") or origin.json().get("origin", {}).get("id")
    resp = client.post(f"/api/origins/{origin_id}/domains", json={"domain_name": f"paypal.{quick_tunnel.ZONE}"},
                       headers=people["alice"]["h"])
    assert resp.status_code == 403
    assert "assigned by the platform" in resp.json()["detail"]


def test_another_user_can_neither_use_nor_see_nor_remove_it(client, people):
    created = _create(client, people["alice"])
    host, origin_id = created["domain_name"], created["origin_id"]

    resp = client.get("/api/tunnels/config-generator", params={"domain": host}, headers=people["bob"]["h"])
    assert resp.status_code == 403
    assert client.get("/api/tunnels/quick", headers=people["bob"]["h"]).json()["tunnels"] == []
    # scope=all from a non-admin is the caller's own list, nothing more
    assert client.get("/api/tunnels/quick", params={"scope": "all"}, headers=people["bob"]["h"]).json()["tunnels"] == []
    assert client.delete(f"/api/tunnels/quick/{origin_id}", headers=people["bob"]["h"]).status_code == 404
    assert quick_tunnel.get(origin_id) is not None


def test_a_user_holds_at_most_the_limit(client, people):
    for _ in range(quick_tunnel.PER_USER):
        _create(client, people["alice"])
    resp = client.post("/api/tunnels/quick", json={"port": 3000}, headers=people["alice"]["h"])
    assert resp.status_code == 400
    assert str(quick_tunnel.PER_USER) in resp.json()["detail"]


def test_the_creation_rate_is_limited(client, people, monkeypatch):
    class _Refuse:
        def is_allowed(self, *a, **k):
            return False, 99, 7200

    monkeypatch.setattr(quick_tunnel, "_limiter", _Refuse())
    resp = client.post("/api/tunnels/quick", json={"port": 3000}, headers=people["alice"]["h"])
    assert resp.status_code == 429
    assert quick_tunnel.count_active(people["alice"]["id"]) == 0


def test_removing_it_frees_everything_and_its_token_stops_working(client, people):
    created = _create(client, people["alice"])
    host, origin_id = created["domain_name"], created["origin_id"]
    token = client.get("/api/tunnels/config-generator", params={"domain": host},
                       headers=people["alice"]["h"]).json()["token"]
    payload = AuthService().decode_token(token)
    assert tunnels_module.tunnel_token_problem(payload) is None

    resp = client.delete(f"/api/tunnels/quick/{origin_id}", headers=people["alice"]["h"])
    assert resp.status_code == 200, resp.text

    assert "no longer exists" in tunnels_module.tunnel_token_problem(payload)
    assert quick_tunnel.get(origin_id) is None
    assert pool.q1("SELECT 1 AS x FROM origins WHERE id = %s::uuid", (origin_id,)) is None
    assert pool.q1("SELECT 1 AS x FROM domains WHERE domain_name = %s", (host,)) is None
    removed = pool.q1("SELECT details FROM audit_logs WHERE scope_id = 'global' AND action = 'quick_tunnel.remove'")
    assert removed["details"]["domain_name"] == host
    assert removed["details"]["owner_user_id"] == people["alice"]["id"]


def test_an_admin_lists_everyone_without_their_port_and_can_remove_any(client, people):
    created = _create(client, people["alice"], port=5173)
    listed = client.get("/api/tunnels/quick", params={"scope": "all"}, headers=people["admin"]["h"]).json()
    assert listed["scope"] == "all"
    row = next(t for t in listed["tunnels"] if t["domain_name"] == created["domain_name"])
    assert row["owner_username"] == "qt_alice"
    assert row["port"] is None

    resp = client.delete(f"/api/tunnels/quick/{created['origin_id']}", headers=people["admin"]["h"])
    assert resp.status_code == 200
    details = pool.q1("SELECT details FROM audit_logs WHERE action = 'quick_tunnel.remove'")["details"]
    assert details["reason"] == "removed by admin"


def test_the_gatekeeper_binds_the_proxy_for_its_owner(client, people):
    host = _create(client, people["alice"])["domain_name"]
    token = client.get("/api/tunnels/config-generator", params={"domain": host},
                       headers=people["alice"]["h"]).json()["token"]
    import asyncio
    verdict = asyncio.run(tunnels_module.frp_webhook_gatekeeper({"op": "NewProxy", "content": {
        "proxy_name": host, "proxy_type": "http", "custom_domains": [host], "metas": {"token": token},
        "user": {"user": "", "metas": None}}}))
    assert verdict["reject"] is False, verdict


def test_the_list_shows_a_connected_agent_as_online_with_no_expiry(client, people, monkeypatch):
    host = _create(client, people["alice"])["domain_name"]

    async def live(force=False):
        return [{"name": host, "status": "online", "conf": {"customDomains": [host]}}]
    monkeypatch.setattr(origin_service, "get_live_proxies", live)
    row = client.get("/api/tunnels/quick", headers=people["alice"]["h"]).json()["tunnels"][0]
    assert row["is_online"] is True
    assert row["expires_at"] is None


def test_an_idle_one_is_removed_and_a_connected_one_is_kept(client, people):
    idle = _create(client, people["alice"])["domain_name"]
    live = _create(client, people["alice"])["domain_name"]
    old = timedelta(days=quick_tunnel.IDLE_DAYS + 1)
    pool.exec_("UPDATE quick_tunnels SET created_at = now() - %s", (old,))

    removed = quick_tunnel.expire_idle({live})
    assert removed == [idle]
    kept = pool.q1("SELECT last_seen_at FROM quick_tunnels WHERE domain_name = %s", (live,))
    assert kept["last_seen_at"] is not None


def test_names_are_in_the_zone_and_hard_to_guess():
    names = {quick_tunnel.new_hostname() for _ in range(200)}
    assert len(names) == 200
    assert all(NAME.match(n) for n in names)
    assert quick_tunnel.in_zone(f"x.{quick_tunnel.ZONE}.")
    assert quick_tunnel.in_zone(quick_tunnel.ZONE)
    assert not quick_tunnel.in_zone(f"x{quick_tunnel.ZONE}")
    assert not quick_tunnel.in_zone("shop.example.com")


@pytest.mark.email_unverified
def test_an_unverified_account_cannot_create_one(client, register_user, auth_header):
    register_user(email="qt-first@example.com", username="qt_first")
    user = register_user(email="qt-new@example.com", username="qt_new")
    resp = client.post("/api/tunnels/quick", json={"port": 3000}, headers=auth_header(user["access_token"]))
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "email_unverified"
