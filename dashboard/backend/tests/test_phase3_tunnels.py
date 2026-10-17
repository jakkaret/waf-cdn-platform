"""Phase 3 of the remediation plan (security audit run 1): tunnels and domain
ownership. One test (or a few) per row of each task's "done when" table."""
import asyncio
import os
import subprocess
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.domains as domains_module
import api.tunnels as tunnels
import services.origin_service as origin_service
from services import dns_service
from services.dynamodb_service import DynamoDBService
from tests.helpers.seed import ensure_user, make_domain, make_origin, make_tunnel_owner, uid

REPO = Path(__file__).resolve().parents[3]


def _run(coro):
    return asyncio.run(coro)


def _token(user_id, domain, days=1):
    return tunnels.auth_service.create_access_token(
        {"sub": user_id, "user_id": user_id, "domain": domain, "type": "tunnel_token"},
        expires_delta=timedelta(days=days))


def _newproxy(token, domain, name=None):
    # Real frpc proxy name: the domain with dots as dashes (config-generator).
    name = name if name is not None else str(domain).strip().lower().rstrip(".")
    return {"op": "NewProxy", "content": {"proxy_name": name, "custom_domains": [domain], "metas": {"token": token}}}


# ------------------------------------------------- P3.1 webhook from frps only

@pytest.fixture()
def hook_client(monkeypatch):
    monkeypatch.setattr(tunnels, "FRP_HOOK_SECRET", "hook-secret-0123456789")
    app = FastAPI()
    app.include_router(tunnels.router)
    return app


def _client_from(app, host):
    return TestClient(app, client=(host, 50000))


LOGIN = {"op": "Login", "content": {"privilege_key": "", "metadatas": {}}}


def test_hook_without_the_secret_or_from_outside_is_a_404(hook_client):
    local = _client_from(hook_client, "127.0.0.1")
    assert local.post("/api/tunnels/frp-hook", json=LOGIN).status_code in (404, 405)  # old path is gone
    assert local.post("/api/tunnels/frp-hook/wrong", json=LOGIN).status_code == 404
    remote = _client_from(hook_client, "172.18.0.1")  # Caddy / docker gateway
    assert remote.post("/api/tunnels/frp-hook/hook-secret-0123456789", json=LOGIN).status_code == 404


def test_hook_from_local_frps_with_the_secret_is_answered(hook_client):
    local = _client_from(hook_client, "127.0.0.1")
    resp = local.post("/api/tunnels/frp-hook/hook-secret-0123456789", json=LOGIN)
    assert resp.status_code == 200
    assert resp.json()["reject"] is True  # no credentials in this Login -- but the gatekeeper answered


def test_hook_is_refused_when_no_secret_is_configured(hook_client, monkeypatch):
    monkeypatch.setattr(tunnels, "FRP_HOOK_SECRET", "")
    local = _client_from(hook_client, "127.0.0.1")
    assert local.post("/api/tunnels/frp-hook/", json=LOGIN).status_code in (404, 405)
    assert local.post("/api/tunnels/frp-hook/anything", json=LOGIN).status_code == 404


def test_caddy_answers_404_for_the_hook_on_public_hosts():
    text = (REPO / "nginx/Caddyfile").read_text()
    matcher = [line for line in text.splitlines() if "@internal_ml_relay path" in line][0]
    assert "/api/tunnels/frp-hook*" in matcher


def test_newproxy_records_the_owner_in_the_database():
    owner = make_tunnel_owner("owned.example.com")
    result = _run(tunnels.frp_webhook_gatekeeper(_newproxy(_token(owner, "owned.example.com"), "owned.example.com",
                                                           name="owned.example.com")))
    assert result["reject"] is False
    assert DynamoDBService().get_proxy_owner("owned.example.com") == owner
    assert tunnels.get_proxy_owner("owned.example.com") == owner  # survives a restart: no process state


# ------------------------------------- P3.2 tokens for verified domains only

def test_removing_the_domain_stops_the_existing_token():
    owner = make_tunnel_owner("gone.example.com")
    token = _token(owner, "gone.example.com")
    assert _run(tunnels.frp_webhook_gatekeeper(_newproxy(token, "gone.example.com")))["reject"] is False
    db = DynamoDBService()
    db.delete_domain(db.get_verified_domain("gone.example.com")["id"])
    result = _run(tunnels.frp_webhook_gatekeeper(_newproxy(token, "gone.example.com")))
    assert result["reject"] is True and "no longer valid" in result["reject_reason"]


# ---------------------------------------------------- P3.3 one canonical form

@pytest.mark.parametrize("spelling", ["Owned2.Example.com", "owned2.example.com.", "OWNED2.EXAMPLE.COM."])
def test_newproxy_treats_every_spelling_as_the_same_host(spelling):
    owner = make_tunnel_owner("owned2.example.com")
    result = _run(tunnels.frp_webhook_gatekeeper(_newproxy(_token(owner, "owned2.example.com"), spelling)))
    assert result["reject"] is False


@pytest.mark.parametrize("bad", ["a b.example.com", "x.com\";curl", "under_score.example.com", "-x.example.com"])
def test_newproxy_refuses_a_malformed_custom_domain(bad):
    owner = make_tunnel_owner("owned3.example.com")
    result = _run(tunnels.frp_webhook_gatekeeper(_newproxy(_token(owner, "owned3.example.com"), bad)))
    assert result["reject"] is True


def test_database_refuses_non_canonical_names():
    owner = ensure_user(uid("canon-owner"))
    origin = make_origin({"user_id": owner})
    db = DynamoDBService()
    db.create_domain({"origin_id": origin["id"], "domain_name": "Trailing.Example.com."})  # canonicalised on write
    assert db.get_domain_by_name("trailing.example.com")
    with pytest.raises(Exception):
        db.create_domain({"origin_id": origin["id"], "domain_name": "bad_name.example.com"})


# ------------------------------------------------- P3.4 CNAME bound to the record

def test_cname_must_carry_this_records_token(monkeypatch):
    monkeypatch.setenv("WAF_CNAME_TARGET", "cdn.waf-it-kku.online")
    target = dns_service.record_cname_target("waf-token-abc")
    assert target == "waf-token-abc.cdn.waf-it-kku.online"
    for cname, expected in [
        ("waf-token-abc.cdn.waf-it-kku.online", True),
        ("WAF-TOKEN-ABC.cdn.waf-it-kku.online.", True),
        ("cdn.waf-it-kku.online", False),                       # the shared target proves nothing
        ("waf-token-abc.cdn.waf-it-kku.online.evil.net", False),
        ("xwaf-token-abc.cdn.waf-it-kku.online", False),
        ("waf-token-other.cdn.waf-it-kku.online", False),       # another tenant's record
    ]:
        monkeypatch.setattr(dns_service, "resolve_cname", lambda d, c=cname: c)
        monkeypatch.setattr(dns_service, "resolve_txt", lambda d: [])
        assert dns_service.verify_domain_dns("shop.example.com", "waf-token-abc") is expected, cname


def test_txt_still_verifies(monkeypatch):
    monkeypatch.setattr(dns_service, "resolve_cname", lambda d: "")
    monkeypatch.setattr(dns_service, "resolve_txt",
                        lambda d: ["waf-token-abc"] if d == "_waf-challenge.shop.example.com" else [])
    assert dns_service.verify_domain_dns("shop.example.com", "waf-token-abc") is True
    assert dns_service.verify_domain_dns("shop.example.com", "waf-token-other") is False


# ----------------------------------------------------- P3.5 no squatting

def test_the_tenant_who_proves_dns_gets_a_domain_another_tenant_only_added():
    db = DynamoDBService()
    a = make_origin({"user_id": ensure_user(uid("squatter"))})
    b = make_origin({"user_id": ensure_user(uid("real-owner"))})
    squat = make_domain(a, "contested.example.com", dns_verified=False)
    real = make_domain(b, "contested.example.com", dns_verified=False)  # allowed now: unverified reserves nothing
    domains_module._mark_verified(real["id"])
    assert db.get_verified_domain("contested.example.com")["origin_id"] == b["id"]
    assert db.get_domain(squat["id"]) is None  # the losing unverified row is gone
    from fastapi import HTTPException
    late = make_origin({"user_id": ensure_user(uid("late"))})
    with pytest.raises(Exception):
        make_domain(late, "contested.example.com", dns_verified=True)  # only one verified row, ever


def test_unverified_rows_older_than_seven_days_are_removed():
    from services.retention_worker import expire_unverified_domains
    from db import pool
    origin = make_origin({"user_id": ensure_user(uid("stale-owner"))})
    old = make_domain(origin, "stale.example.com", dns_verified=False)
    fresh = make_domain(origin, "fresh.example.com", dns_verified=False)
    kept = make_domain(origin, "verified-old.example.com", dns_verified=True)
    pool.exec_("UPDATE domains SET created_at = now() - interval '8 days' WHERE id IN (%s, %s)",
               (old["id"], kept["id"]))
    assert expire_unverified_domains() == 1
    db = DynamoDBService()
    assert db.get_domain(old["id"]) is None
    assert db.get_domain(fresh["id"]) and db.get_domain(kept["id"])


def test_domain_quota_per_origin(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setattr(origin_service, "DOMAINS_QUOTA_PER_ORIGIN", 2)
    origin = make_origin({"user_id": ensure_user(uid("quota-owner"))})
    make_domain(origin, "q1.example.com", dns_verified=False)
    make_domain(origin, "q2.example.com", dns_verified=False)
    with pytest.raises(HTTPException) as e:
        domains_module.assert_domain_quota(origin["id"])
    assert e.value.status_code == 400


def test_a_tunnel_host_of_another_origin_cannot_be_added_or_verified():
    from fastapi import HTTPException
    db = DynamoDBService()
    t = make_origin({"user_id": ensure_user(uid("tunnel-holder"))})
    db.update_origin(t["id"], {"tunnel_domains": ["tunnelled.example.com"]})
    with pytest.raises(HTTPException) as e:
        domains_module.assert_domain_available("tunnelled.example.com", origin_id=str(uid("x")))
    assert e.value.status_code == 400
    other = make_origin({"user_id": ensure_user(uid("other"))})
    row = make_domain(other, "tunnelled.example.com", dns_verified=False)
    with pytest.raises(HTTPException) as e:
        domains_module._mark_verified(row["id"])
    assert e.value.status_code == 409


def test_admin_can_release_a_stale_unverified_domain(app, register_user, auth_header):
    app.include_router(domains_module.router)
    client = TestClient(app)
    admin = register_user(email="rel-admin@example.com", username="rel_admin")  # first user = admin
    user = register_user(email="rel-user@example.com", username="rel_user")
    origin = make_origin({"user_id": user["user"]["user_id"]})
    stale = make_domain(origin, "held.example.com", dns_verified=False)
    held = make_domain(origin, "kept.example.com", dns_verified=True)
    url = "/api/domains/admin/{}/release"
    assert client.delete(url.format(stale["id"]), headers=auth_header(user["access_token"])).status_code == 403
    assert client.delete(url.format(held["id"]), headers=auth_header(admin["access_token"])).status_code == 400
    assert client.delete(url.format(stale["id"]), headers=auth_header(admin["access_token"])).status_code == 200
    assert DynamoDBService().get_domain(stale["id"]) is None


# ------------------------------------------------ P3.6 closing really closes

def test_deleted_users_token_is_refused():
    from services.pg_store import PgUserRepository
    owner = make_tunnel_owner("leaver.example.com")
    token = _token(owner, "leaver.example.com")
    PgUserRepository().delete(owner)
    for op in ({"op": "Login", "content": {"metadatas": {"token": token}}},
               _newproxy(token, "leaver.example.com")):
        assert _run(tunnels.frp_webhook_gatekeeper(op))["reject"] is True


def test_archiving_an_origin_revokes_its_agent_credential_and_tunnel_tokens():
    db = DynamoDBService()
    owner = make_tunnel_owner("archived-site.example.com")
    origin_id = db.get_verified_domain("archived-site.example.com")["origin_id"]
    db.update_origin(origin_id, {"tunnel_token_hash": "a" * 64, "tunnel_domains": ["agent-host.example.com"]})
    assert db.get_agent_credential(origin_id)
    db.delete_origin(origin_id)
    assert db.get_agent_credential(origin_id) is None
    token = _token(owner, "archived-site.example.com")
    assert _run(tunnels.frp_webhook_gatekeeper(_newproxy(token, "archived-site.example.com")))["reject"] is True


@pytest.mark.parametrize("status", ["archived", "deleted", "pending"])
def test_verify_agent_accepts_only_an_active_origin(status):
    import hashlib
    from api import tunnel as tunnel_api
    db = DynamoDBService()
    origin = make_origin({"user_id": ensure_user(uid("agent-owner"))}, status="active")
    secret = "s" * 64
    db.update_origin(origin["id"], {"tunnel_token_hash": hashlib.sha256(secret.encode()).hexdigest(),
                                    "tunnel_domains": ["agent.example.com"]})
    req = tunnel_api.VerifyAgentRequest(token=f"cwt_{origin['id']}_{secret}", domains=["agent.example.com"])
    assert _run(tunnel_api.verify_agent(req))["status"] == "authorized"
    from db import pool
    pool.exec_("UPDATE origins SET status = %s WHERE id = %s", (status, origin["id"]))
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        _run(tunnel_api.verify_agent(req))
    assert e.value.status_code == 401


# --------------------------------------------- P3.7 exact ownership in views

def _frp(proxies):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"proxies": proxies}
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def test_two_tenants_with_lookalike_names_see_only_their_own_tunnel(app, register_user, auth_header, monkeypatch):
    monkeypatch.setenv("FRP_ADMIN_USER", "a")
    monkeypatch.setenv("FRP_ADMIN_PASS", "b")
    monkeypatch.setattr(origin_service, "auto_sync_tunnel_origins", AsyncMock(return_value=[]))
    tunnels._TUNNELS_CACHE.clear()
    app.include_router(tunnels.router)
    client = TestClient(app)
    register_user(email="look-admin@example.com", username="look_admin")
    alice = register_user(email="alice@example.com", username="alice_l")
    bob = register_user(email="bob@example.com", username="bob_l")
    for user, host in ((alice, "shop.example.com"), (bob, "shop.example.com.bob.net")):
        origin = make_origin({"user_id": user["user"]["user_id"]}, label=f"Tunnel ({host})", ip=host)
        make_domain(origin, host)
        DynamoDBService().set_proxy_owner(host.replace(".", "-"), user["user"]["user_id"], host)
    proxies = [{"name": h.replace(".", "-"), "status": "online", "conf": {"customDomains": [h]}}
               for h in ("shop.example.com", "shop.example.com.bob.net")]
    with patch("api.tunnels.httpx.AsyncClient", return_value=_frp(proxies)):
        seen_a = client.get("/api/tunnels/status", headers=auth_header(alice["access_token"])).json()
        tunnels._TUNNELS_CACHE.clear()
        seen_b = client.get("/api/tunnels/status", headers=auth_header(bob["access_token"])).json()
    assert [t["domain"] for t in seen_a["tunnels"]] == ["shop.example.com"]
    assert [t["domain"] for t in seen_b["tunnels"]] == ["shop.example.com.bob.net"]


def test_deregister_takes_an_exact_origin_id_and_404s_otherwise(app, register_user, auth_header):
    app.include_router(tunnels.router)
    client = TestClient(app)
    admin = register_user(email="dr-admin@example.com", username="dr_admin")
    user = register_user(email="dr-user@example.com", username="dr_user")
    origin = make_origin({"user_id": user["user"]["user_id"]}, label="Tunnel (dr.example.com)", ip="dr.example.com")
    for who in (admin, user):
        for target in ("dr.example.com", "dr", str(uid("nope"))):
            assert client.delete(f"/api/tunnels/{target}", headers=auth_header(who["access_token"])).status_code == 404
    assert client.delete(f"/api/tunnels/{origin['id']}", headers=auth_header(user["access_token"])).status_code == 200
    assert DynamoDBService().get_origin_by_id(origin["id"])["status"] == "archived"


# --------------------------------------------- P3.8 legacy route and downloads

def test_legacy_tunnel_verify_route_is_gone(client):
    assert client.post("/api/auth/tunnel/verify", json={"waf_token": "x"}).status_code in (404, 405)


def test_validate_ip_refuses_names_that_are_internal(monkeypatch):
    assert not origin_service.validate_ip("host.docker.internal")
    assert not origin_service.validate_ip("printer.local")
    monkeypatch.setattr(origin_service, "_resolve_addresses", lambda h: ["127.0.0.1"])
    assert not origin_service.validate_ip("rebind.example.com")
    monkeypatch.setattr(origin_service, "_resolve_addresses", lambda h: ["93.184.216.34"])
    assert origin_service.validate_ip("public.example.com")
    monkeypatch.setattr(origin_service, "_resolve_addresses", lambda h: [])
    assert origin_service.validate_ip("not-yet-in-dns.example.com")


def test_deploy_site_route_checks_the_origin_address():
    from services import nginx_site_service as nss
    with pytest.raises(ValueError):
        nss.deploy_site_route("site.example.com", {"ip": "127.0.0.1", "port": 80})
    assert not hasattr(nss, "sync_all_verified_sites")


def _install_env(tmp_path, tarball: bytes):
    """Run the install script against stubs: curl serves `tarball`, nothing
    touches the real /etc or /usr."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "frp.tgz").write_bytes(tarball)
    (bin_dir / "curl").write_text(
        "#!/bin/bash\n"
        "out=''; while [[ $# -gt 0 ]]; do [[ $1 == -o ]] && { out=$2; shift; }; shift; done\n"
        f"if [[ -n $out ]]; then cp '{tmp_path}/frp.tgz' \"$out\"; else echo legacy-secret; fi\n")
    for name in ("systemctl",):
        (bin_dir / name).write_text("#!/bin/bash\nexit 0\n")
    (bin_dir / "uname").write_text("#!/bin/bash\necho x86_64\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    script = tunnels.INSTALL_AGENT_SCRIPT
    script = script.replace("/etc/waf-agent", str(tmp_path / "etc-waf-agent"))
    script = script.replace("/usr/local/bin/waf-agent", str(tmp_path / "waf-agent"))
    script = script.replace("/etc/systemd/system", str(tmp_path))
    (tmp_path / "install.sh").write_text(script)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    return subprocess.run(["bash", str(tmp_path / "install.sh"), "--token", "t", "--domain", "a.example.com"],
                          env=env, capture_output=True, text=True, timeout=30)


def test_install_script_stops_when_the_checksum_does_not_match(tmp_path):
    result = _install_env(tmp_path, b"not the real frp release")
    assert result.returncode != 0
    assert "SHA-256" in result.stderr
    assert not (tmp_path / "waf-agent").exists()  # nothing installed


def test_install_script_pins_both_architectures_and_the_docker_image():
    script = tunnels.INSTALL_AGENT_SCRIPT
    assert "bff260b68ca7b1461182a46c4f34e9709ba32764eed30a15dd94ac97f50a2c40" in script  # amd64
    assert "af6366f2b43920ebfe6235dba6060770399ed1fb18601e5818552bd46a7621f8" in script  # arm64
    assert tunnels.FRPC_IMAGE.startswith("snowdreamtech/frpc:0.61.1@sha256:")
