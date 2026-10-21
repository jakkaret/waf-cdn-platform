"""Connect-a-site flow (2026-10-10): api/onboarding.py /inspect, /connect,
/progress, the direct-mode route reconcile in services/nginx_site_service.py,
services/site_connect.py, the DNS worker's backoff, and auto-sync adopting an
agent-mode origin instead of creating a duplicate.

The rule every test here leans on: origins created before the connect flow
(no connection_mode) must keep working exactly as before.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import api.domains as domains_module
import api.onboarding as onboarding_module
import api.tunnels as tunnels_module
import services.dns_verification_worker as worker_module
import services.nginx_site_service as nss
import services.origin_service as origin_service
import services.site_connect as site_connect
from api import auth as auth_module
from api import origins as origins_module
from services.nginx_site_service import reconcile_site_routes
from services.rate_limiter import limiter
from tests.helpers.seed import ensure_user, seed_domain, seed_origin, uid

DIRECT_IP = {"id": uid("o-direct"), "ip": "203.0.113.10", "port": 443, "origin_scheme": "https",
             "connection_mode": "direct", "status": "pending"}


# --------------------------------------------------------------- nginx text

def test_https_ip_origin_gets_the_visitors_host_and_sni():
    text = nss.generate_site_nginx_config("shop.example.com", DIRECT_IP)
    assert "proxy_pass https://203.0.113.10;" in text
    assert "proxy_set_header Host $host;" in text
    assert "proxy_ssl_name $host;" in text
    assert "proxy_set_header Host 203.0.113.10;" not in text


def test_https_hostname_origin_keeps_its_own_name():
    # A PaaS app routes on its own hostname; that behaviour is unchanged.
    text = nss.generate_site_nginx_config("shop.example.com", {"ip": "app.herokuapp.com", "port": 443})
    assert "proxy_set_header Host app.herokuapp.com;" in text
    assert "proxy_ssl_name app.herokuapp.com;" in text


def test_https_on_a_non_standard_port_keeps_the_port():
    text = nss.generate_site_nginx_config(
        "shop.example.com", {"ip": "203.0.113.10", "port": 8443, "origin_scheme": "https"})
    assert "proxy_pass https://203.0.113.10:8443;" in text


def test_plain_http_origin_is_unchanged():
    text = nss.generate_site_nginx_config("shop.example.com", {"ip": "203.0.113.10", "port": 8080})
    assert "proxy_pass http://203.0.113.10:8080;" in text
    assert "proxy_ssl_name" not in text


def test_generated_text_is_identical_on_every_call():
    # reconcile compares bytes; a timestamp in the header would rewrite and
    # reload nginx on every tick.
    a = nss.generate_site_nginx_config("shop.example.com", DIRECT_IP)
    b = nss.generate_site_nginx_config("shop.example.com", DIRECT_IP)
    assert a == b


# --------------------------------------------------------------- reconcile

def test_only_verified_active_direct_origins_are_desired():
    origins = [
        DIRECT_IP,
        {"id": uid("o-legacy"), "ip": "203.0.113.20", "port": 80},  # no connection_mode
        {"id": uid("o-agent"), "ip": "a.example.com", "port": 3000, "connection_mode": "agent"},
        {"id": uid("o-archived"), "ip": "203.0.113.30", "port": 80, "connection_mode": "direct", "status": "archived"},
    ]
    domains = [
        {"origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True},
        {"origin_id": uid("o-direct"), "domain_name": "pending.example.com", "dns_verified": False},
        {"origin_id": uid("o-legacy"), "domain_name": "legacy.example.com", "dns_verified": True},
        {"origin_id": uid("o-agent"), "domain_name": "a.example.com", "dns_verified": True},
        {"origin_id": uid("o-archived"), "domain_name": "gone.example.com", "dns_verified": True},
    ]
    assert set(nss.desired_direct_sites(domains, origins)) == {"shop.example.com"}


class FakeContainer:
    """Stands in for `docker exec` against waf-nginx's conf.d."""

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.reloads = 0
        self.commands = []

    def _tar(self) -> bytes:
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            entries = {"default.conf": "server { listen 8080 default_server; }"}
            entries.update({f"site-{d}.conf": t for d, t in self.files.items()})
            for name, text in entries.items():
                data = text.encode()
                info = tarfile.TarInfo(f"./{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def docker(self, args, input_text=None):
        cmd = args[0]
        self.commands.append(cmd)
        if cmd == "tar":
            return MagicMock(returncode=0, stdout=self._tar(), stderr=b"")
        path = args[-1]  # tee PATH / rm -f PATH
        domain = path.rsplit("/site-", 1)[-1][:-len(".conf")]
        if cmd == "tee":
            self.files[domain] = input_text
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        if cmd == "rm":
            self.files.pop(domain, None)
            return MagicMock(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError(args)


@pytest.fixture()
def container(monkeypatch, tmp_path):
    c = FakeContainer()
    monkeypatch.setattr(nss, "_docker", c.docker)
    monkeypatch.setattr(nss, "PERSISTENT_SITES_DIR", tmp_path)
    monkeypatch.setattr(nss.rule_mgr, "test_nginx", lambda: None)

    def _reload():
        c.reloads += 1
    monkeypatch.setattr(nss.rule_mgr, "reload_nginx", _reload)
    return c


MANAGED = nss.MANAGED_MARKER + "\nserver { }"


def _seed(origins, domains):
    for o in origins:
        seed_origin(nss.db, o)
    for d in domains:
        seed_domain(nss.db, d)


def test_reconcile_adds_the_missing_route_and_activates_the_origin(container):
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    summary = reconcile_site_routes()
    assert summary["added"] == ["shop.example.com"]
    assert container.files["shop.example.com"].startswith(nss.MANAGED_MARKER)
    assert container.reloads == 1
    assert nss.deployed_direct_domains() == {"shop.example.com"}
    assert nss.db.get_origin_by_id(uid("o-direct"))["status"] == "active"


def test_reconcile_is_a_no_op_when_nothing_changed(container):
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    reconcile_site_routes()
    summary = reconcile_site_routes()
    assert summary == {"added": [], "updated": [], "removed": [], "failed": []}
    assert container.reloads == 1  # no second reload


def test_reconcile_never_touches_routes_of_pre_existing_origins(container):
    # e.g. scripts/qa/seed.py's hand-deployed Mode A routes
    container.files["legacy.example.com"] = "server { }"
    _seed([{"id": uid("o-legacy"), "ip": "203.0.113.20", "port": 80}],
          [{"id": uid("d1"), "origin_id": uid("o-legacy"), "domain_name": "legacy.example.com", "dns_verified": True}])
    summary = reconcile_site_routes()
    assert summary["removed"] == []
    assert "legacy.example.com" in container.files
    assert container.reloads == 0


def test_reconcile_removes_its_own_routes_of_deleted_domains_and_archived_origins(container):
    container.files["deleted.example.com"] = MANAGED
    container.files["archived.example.com"] = MANAGED
    _seed([dict(DIRECT_IP, id=uid("o-arch"), status="archived")],
          [{"id": uid("d1"), "origin_id": uid("o-arch"), "domain_name": "archived.example.com", "dns_verified": True}])
    summary = reconcile_site_routes()
    assert summary["removed"] == ["archived.example.com", "deleted.example.com"]
    assert container.files == {}


def test_review6_a_hand_placed_file_without_a_db_row_is_kept(container):
    # Review finding 6: files with no domain row used to be deleted.
    container.files["status.example.org"] = "server { server_name status.example.org; }"
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    summary = reconcile_site_routes()
    assert summary["removed"] == []
    assert "status.example.org" in container.files


def test_reconcile_keeps_files_when_the_domains_table_reads_empty(container):
    container.files["shop.example.com"] = MANAGED
    summary = reconcile_site_routes()
    assert summary["removed"] == []
    assert "shop.example.com" in container.files


def test_reconcile_undoes_a_refused_file_and_does_not_reload(container, monkeypatch):
    container.files["legacy.example.com"] = "old text"
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    _nginx_rejects(container, monkeypatch, marker="203.0.113.10")  # only the new file is bad
    summary = reconcile_site_routes()
    assert summary["failed"] == ["shop.example.com"]
    assert container.files == {"legacy.example.com": "old text"}
    assert container.reloads == 0
    assert nss.deployed_direct_domains() == set()


def test_review9_site_files_are_read_with_one_exec(container):
    for d in ("a.example.com", "b.example.com", "c.example.com"):
        container.files[d] = MANAGED
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    reconcile_site_routes()
    assert container.commands.count("tar") == 1
    assert "cat" not in container.commands


# --------------------------------------------------------------- site_connect

def test_cloudflare_addresses_are_recognised():
    assert site_connect.detect_cdn("104.16.1.1") == "Cloudflare"
    assert site_connect.detect_cdn("203.0.113.10") is None


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "not-an-ip"])
def test_probe_refuses_anything_but_a_public_address(ip):
    with pytest.raises(ValueError):
        site_connect.probe_origin(ip, "shop.example.com")


def _dns(monkeypatch, cname="", a=None, ours=None):
    monkeypatch.setattr(site_connect, "current_dns", lambda d: {"cname": cname, "a": list(a or [])})
    monkeypatch.setattr(site_connect, "platform_ips", lambda: set(ours or []))
    monkeypatch.setenv("WAF_CNAME_TARGET", "cdn.waf-it-kku.online")


def test_inspect_recommends_direct_when_the_current_server_answers(monkeypatch):
    _dns(monkeypatch, a=["203.0.113.10"])
    monkeypatch.setattr(site_connect, "probe_origin", lambda ip, d: {
        "reachable": True, "scheme": "https", "port": 443, "status": 200})
    r = site_connect.inspect_domain("shop.example.com")
    assert r["recommended_mode"] == "direct"
    assert r["origin"] == {"ip": "203.0.113.10", "port": 443, "scheme": "https", "status": 200}


def test_inspect_recommends_the_agent_when_the_server_does_not_answer(monkeypatch):
    _dns(monkeypatch, a=["203.0.113.10"])
    monkeypatch.setattr(site_connect, "probe_origin", lambda ip, d: {"reachable": False})
    r = site_connect.inspect_domain("shop.example.com")
    assert (r["recommended_mode"], r["reason"]) == ("agent", "unreachable")


def test_inspect_does_not_probe_a_cdn_address(monkeypatch):
    _dns(monkeypatch, a=["104.16.1.1"])
    monkeypatch.setattr(site_connect, "probe_origin", lambda *a: pytest.fail("probed a CDN address"))
    r = site_connect.inspect_domain("shop.example.com")
    assert (r["cdn"], r["reason"], r["recommended_mode"]) == ("Cloudflare", "behind_cdn", "agent")


def test_inspect_notices_a_domain_that_already_points_at_us(monkeypatch):
    _dns(monkeypatch, cname="cdn.waf-it-kku.online", a=["45.154.26.91"], ours=["45.154.26.91"])
    monkeypatch.setattr(site_connect, "probe_origin", lambda *a: pytest.fail("probed our own edge"))
    r = site_connect.inspect_domain("shop.example.com")
    assert r["already_points_to_platform"] is True


# --------------------------------------------------------------- API

@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    test_app.include_router(onboarding_module.router)
    return test_app


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: False)
    monkeypatch.setattr(site_connect, "current_dns", lambda d: {"cname": "", "a": ["203.0.113.10"]})
    monkeypatch.setattr(site_connect, "platform_ips", lambda: {"45.154.26.91"})
    monkeypatch.setenv("WAF_CNAME_TARGET", "cdn.waf-it-kku.online")
    onboarding_module._last_verify.clear()
    onboarding_module._last_route.clear()
    onboarding_module._last_https_probe.clear()
    onboarding_module._last_frp_poll.clear()
    origin_service._LIVE_PROXIES_CACHE = None


@pytest.fixture()
def tenant(register_user, auth_header):
    register_user(email="admin-first@example.com", username="admin_first")  # first user = admin
    user = register_user(email="tenant@example.com", username="tenant_user")
    return {"headers": auth_header(user["access_token"])}


def _origins():
    return nss.db.list_origins()


def test_connect_with_the_agent_creates_one_origin_and_one_domain(client, tenant):
    r = client.post("/api/onboarding/connect", headers=tenant["headers"],
                    json={"domain": "Shop.Example.com", "mode": "agent", "port": 3000})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["connection_mode"] == "agent"
    assert body["verified"] is False
    assert body["dns_instructions"]["required"] == ["cname_record"]
    # P3.4: the CNAME target carries this record's own token
    cname = body["dns_instructions"]["cname_record"]["value"]
    assert cname.startswith("waf-token-") and cname.endswith(".cdn.waf-it-kku.online")
    [origin] = _origins()
    # The address is the domain: that is what auto-sync matches the tunnel on.
    assert (origin["label"], origin["ip"], origin["port"]) == ("shop.example.com", "shop.example.com", 3000)
    assert origin["connection_mode"] == "agent"


def test_connect_direct_stores_the_address_and_scheme(client, tenant):
    r = client.post("/api/onboarding/connect", headers=tenant["headers"], json={
        "domain": "shop.example.com", "mode": "direct", "port": 443, "origin_address": "203.0.113.10"})
    assert r.status_code == 200, r.text
    [origin] = _origins()
    assert (origin["ip"], origin["port"], origin["origin_scheme"]) == ("203.0.113.10", 443, "https")


@pytest.mark.parametrize("address,detail", [
    ("10.0.0.5", "public"),
    ("", "required"),
    ("45.154.26.91", "edge"),
    ("shop.example.com", "public IP"),  # a hostname, and the domain itself
])
def test_connect_direct_refuses_bad_addresses_without_creating_anything(client, tenant, address, detail):
    r = client.post("/api/onboarding/connect", headers=tenant["headers"], json={
        "domain": "shop.example.com", "mode": "direct", "port": 80, "origin_address": address})
    assert r.status_code == 400
    assert detail in r.json()["detail"]
    assert _origins() == []


def test_connect_refuses_a_taken_domain_before_creating_an_origin(client, tenant):
    first = client.post("/api/onboarding/connect", headers=tenant["headers"],
                        json={"domain": "shop.example.com", "mode": "agent", "port": 3000})
    assert first.status_code == 200
    again = client.post("/api/onboarding/connect", headers=tenant["headers"],
                        json={"domain": "shop.example.com", "mode": "agent", "port": 3000})
    assert again.status_code == 400
    assert len(_origins()) == 1


def test_connect_refuses_platform_subdomains_for_tenants(client, tenant):
    r = client.post("/api/onboarding/connect", headers=tenant["headers"],
                    json={"domain": "mine.waf-it-kku.online", "mode": "agent", "port": 3000})
    assert r.status_code == 403
    assert _origins() == []


def test_a_failed_domain_create_rolls_the_origin_back(client, tenant, monkeypatch):
    from fastapi import HTTPException

    def _boom(*_a, **_k):
        raise HTTPException(status_code=500, detail="Failed to save domain")
    monkeypatch.setattr(domains_module, "create_domain_record", _boom)
    r = client.post("/api/onboarding/connect", headers=tenant["headers"],
                    json={"domain": "shop.example.com", "mode": "agent", "port": 3000})
    assert r.status_code == 500
    assert _origins() == []


def test_connect_verifies_at_once_when_dns_already_points_at_us(client, tenant, monkeypatch):
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    r = client.post("/api/onboarding/connect", headers=tenant["headers"],
                    json={"domain": "shop.example.com", "mode": "agent", "port": 3000})
    assert r.json()["verified"] is True
    [row] = nss.db.list_domains()
    assert row["dns_verified"] is True


def _connect(client, tenant, **extra):
    body = {"domain": "shop.example.com", "mode": "agent", "port": 3000, **extra}
    return client.post("/api/onboarding/connect", headers=tenant["headers"], json=body).json()["origin_id"]


def test_progress_reports_pending_dns_with_the_current_answer(client, tenant):
    origin_id = _connect(client, tenant)
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    [d] = p["domains"]
    assert d["dns"]["status"] == "pending"
    assert d["dns"]["current"] == {"cname": "", "a": ["203.0.113.10"], "cname_ok": False, "txt_ok": False,
                                   "points_here": False}
    assert d["connection"]["status"] == "waiting_dns"  # P3.2: no agent token before DNS proves ownership
    assert d["ready"] is False and p["all_ready"] is False


def test_progress_says_a_live_site_verified_by_txt_still_needs_its_cname_moved(client, tenant, monkeypatch):
    """TXT-first for a live site: ownership is proven while the name still
    sends visitors to the old host. The page must keep showing the CNAME step,
    not "points at us"."""
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(site_connect, "current_dns",
                        lambda d: {"cname": "old.vercel-dns-017.com", "a": ["216.198.79.1"], "via": "authoritative",
                                   "nameserver": "ns1.example.net", "txt_challenge": []})
    [d] = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()["domains"]
    assert d["dns"]["status"] == "verified"
    assert d["dns"]["current"]["points_here"] is False
    assert d["dns"]["current"]["cname"] == "old.vercel-dns-017.com"
    assert d["ready"] is False


def test_progress_drops_the_dns_detail_once_the_name_points_here(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(site_connect, "current_dns",
                        lambda d: {"cname": "waf-token-x.cdn.waf-it-kku.online", "a": ["45.154.26.91"]})
    [d] = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()["domains"]
    assert d["dns"]["status"] == "verified"
    assert d["dns"]["current"] is None


def test_progress_checks_dns_at_most_once_per_throttle_window(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant)
    calls = []
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: calls.append(d) or False)
    for _ in range(3):
        client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"])
    assert len(calls) == 1


def test_progress_sees_dns_verify_and_the_agent_connect(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    proxies = [{"name": "shop-example-com", "status": "online", "conf": {"customDomains": ["shop.example.com"]}}]
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=proxies))
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    [d] = p["domains"]
    assert d["dns"]["status"] == "verified"
    assert d["connection"]["status"] == "connected"
    assert d["https"]["status"] == "pending"  # no cert probe yet -> not ready
    assert d["ready"] is False


def test_progress_activates_an_agent_origin_once_its_tunnel_is_seen(client, tenant, monkeypatch):
    # The header used to stay PENDING next to a connected card until someone
    # opened the Origins list (auto-sync).
    origin_id = _connect(client, tenant)
    proxies = [{"name": "shop-example-com", "status": "online", "conf": {"customDomains": ["shop.example.com"]}}]
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=proxies))
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["origin_status"] == "active"
    [origin] = _origins()
    assert (origin["status"], origin["is_tunnel"], origin["tunnel_name"]) == ("active", True, "shop-example-com")


def test_progress_leaves_a_waiting_agent_origin_pending(client, tenant):
    origin_id = _connect(client, tenant)
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["origin_status"] == "pending"


def test_progress_for_direct_mode_follows_the_deployed_route(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant, mode="direct", port=443, origin_address="203.0.113.10")
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["domains"][0]["connection"]["status"] == "configuring"
    monkeypatch.setattr(nss, "_deployed_domains", {"shop.example.com"})
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["domains"][0]["connection"]["status"] == "connected"


def test_progress_does_not_claim_a_connection_for_pre_existing_origins(client, tenant):
    r = client.post("/api/origins", headers=tenant["headers"], json={"label": "old", "ip": "203.0.113.9", "port": 80})
    origin_id = r.json()["id"]
    client.post(f"/api/origins/{origin_id}/domains", headers=tenant["headers"], json={"domain_name": "old.example.com"})
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["connection_mode"] is None
    assert p["domains"][0]["connection"]["status"] == "unknown"


def test_progress_is_refused_to_strangers(client, tenant, register_user, auth_header):
    origin_id = _connect(client, tenant)
    stranger = register_user(email="stranger@example.com", username="stranger")
    r = client.get(f"/api/onboarding/progress/{origin_id}", headers=auth_header(stranger["access_token"]))
    assert r.status_code == 403


def test_inspect_short_circuits_a_taken_domain(client, tenant, monkeypatch):
    _connect(client, tenant)
    monkeypatch.setattr(site_connect, "inspect_domain", lambda d: pytest.fail("inspected a taken domain"))
    r = client.post("/api/onboarding/inspect", headers=tenant["headers"], json={"domain": "shop.example.com"})
    assert r.json() == {"domain": "shop.example.com", "already_registered": True}


def test_inspect_is_rate_limited_per_user(client, tenant, monkeypatch):
    limiter_stub = MagicMock()
    limiter_stub.is_allowed.return_value = (False, 0, 120)
    monkeypatch.setattr(onboarding_module, "_inspect_limiter", limiter_stub)
    r = client.post("/api/onboarding/inspect", headers=tenant["headers"], json={"domain": "new.example.com"})
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "120"
    assert limiter_stub.is_allowed.call_args.kwargs["fail_open"] is False


def test_inspect_rejects_a_malformed_domain(client, tenant):
    r = client.post("/api/onboarding/inspect", headers=tenant["headers"], json={"domain": "bad_name.example.com"})
    assert r.status_code == 422


# --------------------------------------------------------------- DNS worker

def test_worker_skips_malformed_names_and_backs_off(monkeypatch):
    calls = []
    monkeypatch.setattr(worker_module, "verify_domain_dns", lambda d, t: calls.append(d) or False)
    monkeypatch.setattr(worker_module, "_next_check", {})
    monkeypatch.setattr(worker_module, "_failures", {})
    monkeypatch.setattr(worker_module, "_reported_invalid", set())
    db = nss.db
    # P3.3: a malformed name can no longer be stored at all (CHECK in 0007),
    # so the worker only ever sees canonical names.
    with pytest.raises(Exception):
        seed_domain(db, {"id": uid("bad"), "domain_name": "waf_project_web.com", "dns_verified": False})
    seed_domain(db, {"id": uid("ok"), "domain_name": "shop.example.com", "dns_verified": False})

    asyncio.run(worker_module.check_pending_domains(db, now=0))
    assert calls == ["shop.example.com"]
    asyncio.run(worker_module.check_pending_domains(db, now=30))   # inside the 60 s backoff
    assert calls == ["shop.example.com"]
    asyncio.run(worker_module.check_pending_domains(db, now=61))
    assert calls == ["shop.example.com", "shop.example.com"]
    assert worker_module.backoff_seconds(2) == 120
    assert worker_module.backoff_seconds(99) == worker_module.MAX_BACKOFF_SECONDS


def test_worker_runs_the_shared_verified_steps(monkeypatch):
    monkeypatch.setattr(worker_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(worker_module, "_next_check", {})
    seen = []

    async def _after(origin_id, name):
        seen.append((origin_id, name))
    monkeypatch.setattr(domains_module, "after_domain_verified", _after)
    db = nss.db
    seed_domain(db, {"id": uid("d1"), "origin_id": uid("o1"), "domain_name": "shop.example.com", "dns_verified": False})
    assert asyncio.run(worker_module.check_pending_domains(db, now=0)) == ["shop.example.com"]
    assert seen == [(uid("o1"), "shop.example.com")]
    assert db.get_domain(uid("d1"))["dns_verified"] is True


# --------------------------------------------------------------- auto-sync

def test_auto_sync_adopts_an_agent_origin_instead_of_duplicating_it(monkeypatch):
    ensure_user(uid("u1"))
    origin_service.create_origin(uid("u1"), label="shop.example.com", ip="shop.example.com", port=3000,
                                 connection_mode="agent", origin_scheme="http")
    origin_service.db.set_proxy_owner("shop-example-com", uid("u1"), "shop.example.com")
    monkeypatch.setattr(origin_service, "verify_domain_dns", lambda d, t: False)
    proxy = {"name": "shop-example-com", "status": "online",
             "conf": {"customDomains": ["shop.example.com"], "metadatas": {"port": "3000"}}}
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=[proxy]))
    try:
        asyncio.run(origin_service.auto_sync_tunnel_origins(uid("u1")))
    finally:
        pass
    [origin] = origin_service.db.list_origins()
    assert origin["status"] == "active"
    assert origin["is_tunnel"] is True
    assert origin["tunnel_name"] == "shop-example-com"


def test_progress_records_the_live_name_of_a_current_agent(client, tenant, monkeypatch):
    # Current agents name their proxy after the domain (frps may prefix the
    # client's user). The connect flow stored "shop-example-com" instead,
    # which never matched, so the origin read as disconnected while online.
    origin_id = _connect(client, tenant)
    live = "tok.shop.example.com"
    proxies = [{"name": live, "status": "online", "conf": {"customDomains": ["shop.example.com"]}}]
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=proxies))
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["origin_status"] == "active"
    [origin] = _origins()
    assert origin["tunnel_name"] == live
    assert origins_module._tunnel_is_online(origin["tunnel_name"], {live}) is True


def test_auto_sync_renames_a_dashed_tunnel_name_to_the_live_proxy(monkeypatch):
    # Origins activated before that fix keep the dashed name; opening the
    # Origins list (auto-sync) moves them to the live proxy name.
    ensure_user(uid("u1"))
    made = origin_service.create_origin(uid("u1"), label="shop.example.com", ip="shop.example.com", port=3000,
                                        connection_mode="agent", origin_scheme="http")
    origin_service.db.update_origin(made["id"], {"status": "active", "is_tunnel": True, "tunnel_name": "shop-example-com"})
    live = "tok.shop.example.com"
    origin_service.db.set_proxy_owner(live, uid("u1"), "shop.example.com")
    monkeypatch.setattr(origin_service, "verify_domain_dns", lambda d, t: False)
    proxy = {"name": live, "status": "online",
             "conf": {"customDomains": ["shop.example.com"], "metadatas": {"port": "3000"}}}
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=[proxy]))
    asyncio.run(origin_service.auto_sync_tunnel_origins(uid("u1")))
    [origin] = origin_service.db.list_origins()
    assert origin["tunnel_name"] == live
    assert origins_module._tunnel_is_online(origin["tunnel_name"], {live}) is True


# --------------------------------------------------------------- review fixes
# Code review of this branch (2026-10-10) findings 1-9.

@pytest.mark.parametrize("address", [
    "host.docker.internal",          # the WAF host's own services
    "127.0.0.1.nip.io",              # public DNS name for a loopback address
    "internal.example.com",          # any name: DNS can change after the check
])
def test_review1_direct_mode_refuses_hostnames(client, tenant, address):
    r = client.post("/api/onboarding/connect", headers=tenant["headers"], json={
        "domain": "shop.example.com", "mode": "direct", "port": 8000, "origin_address": address})
    assert r.status_code == 400
    assert _origins() == []


@pytest.mark.parametrize("address", ["178.104.53.123", "45.154.26.91", "::ffff:178.104.53.123"])
def test_security_direct_mode_refuses_the_platforms_own_hosts(address, monkeypatch):
    # Security review (2026-10-11): the Main host's public IP passed the
    # "public address" check, giving a tenant a proxy into ports that are only
    # open to the WAF's own containers.
    monkeypatch.delenv("WAF_SELF_IPS", raising=False)
    assert nss.direct_upstream_allowed(address) is False
    origin = dict(DIRECT_IP, ip=address, port=8000, origin_scheme="http")
    domains = [{"origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}]
    assert nss.desired_direct_sites(domains, [origin]) == {}


def test_security_self_ips_follow_the_environment(monkeypatch):
    monkeypatch.setenv("WAF_SELF_IPS", "198.51.100.9")
    monkeypatch.setenv("WAF_EDGE_IPS", "198.51.100.10")
    assert nss.direct_upstream_allowed("198.51.100.9") is False
    assert nss.direct_upstream_allowed("198.51.100.10") is False
    assert nss.direct_upstream_allowed("203.0.113.10") is True


def test_review1_reconcile_never_routes_a_direct_origin_to_a_hostname_or_private_ip():
    # Defense in depth for rows written another way (old data, manual edits).
    origins = [
        dict(DIRECT_IP, id="o-host", ip="host.docker.internal", port=8000, origin_scheme="http"),
        dict(DIRECT_IP, id="o-priv", ip="10.0.0.5", port=80, origin_scheme="http"),
        DIRECT_IP,
    ]
    domains = [
        {"origin_id": "o-host", "domain_name": "a.example.com", "dns_verified": True},
        {"origin_id": "o-priv", "domain_name": "b.example.com", "dns_verified": True},
        {"origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True},
    ]
    assert set(nss.desired_direct_sites(domains, origins)) == {"shop.example.com"}


def test_review2_ipv6_origin_is_bracketed():
    text = nss.generate_site_nginx_config(
        "shop.example.com", {"ip": "2606:4700::1", "port": 443, "origin_scheme": "https"})
    assert "proxy_pass https://[2606:4700::1];" in text
    text = nss.generate_site_nginx_config(
        "shop.example.com", {"ip": "2606:4700::1", "port": 8080, "origin_scheme": "http"})
    assert "proxy_pass http://[2606:4700::1]:8080;" in text


def _two_tenants():
    good = dict(DIRECT_IP, id="o-good")
    bad = dict(DIRECT_IP, id="o-bad", ip="203.0.113.66")
    _seed([good, bad], [
        {"id": "d-good", "origin_id": "o-good", "domain_name": "good.example.com", "dns_verified": True},
        {"id": "d-bad", "origin_id": "o-bad", "domain_name": "bad.example.com", "dns_verified": True},
    ])


def _nginx_rejects(container, monkeypatch, marker="203.0.113.66"):
    """nginx -t fails while any site file contains `marker`."""
    def _test():
        if any(marker in t for t in container.files.values()):
            raise RuntimeError("nginx: [emerg] host not found in upstream")
    monkeypatch.setattr(nss.rule_mgr, "test_nginx", _test)

    def _reload():
        _test()
        container.reloads += 1
    monkeypatch.setattr(nss.rule_mgr, "reload_nginx", _reload)


def test_review2_one_bad_site_does_not_block_the_others(container, monkeypatch):
    _two_tenants()
    _nginx_rejects(container, monkeypatch)
    summary = reconcile_site_routes()
    assert "good.example.com" in container.files
    assert "bad.example.com" not in container.files
    assert summary["failed"] == ["bad.example.com"]
    assert container.reloads == 1
    assert nss.deployed_direct_domains() == {"good.example.com"}
    assert "bad.example.com" in nss.failed_direct_domains()


def test_review2_a_bad_site_does_not_block_removals(container, monkeypatch):
    container.files["deleted.example.com"] = nss.MANAGED_MARKER + "\nserver { }"
    _two_tenants()
    _nginx_rejects(container, monkeypatch)
    reconcile_site_routes()
    assert "deleted.example.com" not in container.files


def test_review5_rollback_continues_after_a_docker_error(container, monkeypatch):
    # A failed restore must not stop the remaining restores or hide the cause.
    _two_tenants()
    _nginx_rejects(container, monkeypatch)
    real = container.docker
    calls = {"rm": 0}

    def flaky(args, input_text=None):
        if args[0] == "rm":
            calls["rm"] += 1
            raise OSError("docker: container is restarting")
        return real(args, input_text)
    monkeypatch.setattr(nss, "_docker", flaky)
    summary = reconcile_site_routes()  # must not raise
    assert "bad.example.com" in summary["failed"]
    assert calls["rm"] >= 1
    # The refused file could not be removed, so nginx refuses the reload too;
    # nothing applied this run is reported live.
    assert "reload_error" in summary
    assert nss.deployed_direct_domains() == set()

    # Docker is back: the next run finishes the restore and the reload, and
    # the good tenant goes live without anything else changing.
    monkeypatch.setattr(nss, "_docker", real)
    summary = reconcile_site_routes()
    assert "reload_error" not in summary
    assert container.reloads == 1
    assert nss.deployed_direct_domains() == {"good.example.com"}


def test_review3_viewers_see_status_but_no_token_and_cause_no_writes(client, tenant, register_user, auth_header, monkeypatch):
    origin_id = _connect(client, tenant)
    viewer = register_user(email="viewer@example.com", username="viewer_user")
    r = client.post(f"/api/origins/{origin_id}/viewers", headers=tenant["headers"], json={"email": "viewer@example.com"})
    assert r.status_code == 200, r.text
    checked = []
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: checked.append(d) or True)
    proxies = [{"name": "shop-example-com", "status": "online", "conf": {"customDomains": ["shop.example.com"]}}]
    monkeypatch.setattr(origin_service, "get_live_proxies", AsyncMock(return_value=proxies))

    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=auth_header(viewer["access_token"]))
    assert p.status_code == 200
    body = p.json()
    [d] = body["domains"]
    assert d["dns"]["instructions"]["txt_record"]["value"] == ""   # token withheld
    assert checked == []                                           # no DNS check run for a viewer
    [row] = nss.db.list_domains()
    assert row["dns_verified"] is False
    [origin] = _origins()
    assert origin["status"] == "pending" and not origin.get("is_tunnel")
    assert body["can_edit"] is False


def test_review4_rollback_also_removes_a_domain_row_written_before_the_failure(client, tenant, monkeypatch):
    # create_domain_record can fail after put_item (here: the audit write).
    def _boom(**_kw):
        raise RuntimeError("audit store unavailable")
    monkeypatch.setattr(domains_module.audit_log, "write_audit_event", _boom)
    with pytest.raises(RuntimeError):
        client.post("/api/onboarding/connect", headers=tenant["headers"],
                    json={"domain": "shop.example.com", "mode": "agent", "port": 3000})
    assert _origins() == []
    assert nss.db.list_domains() == []
    monkeypatch.undo()


def test_review7_auto_verified_domains_take_the_one_post_verify_path(client, register_user, auth_header, monkeypatch):
    admin = register_user(email="first-admin@example.com", username="first_admin")  # first user = admin
    h = auth_header(admin["access_token"])
    calls, synced = [], []

    async def _after(origin_id, name):
        calls.append(name)
    monkeypatch.setattr(domains_module, "after_domain_verified", _after)
    monkeypatch.setattr(domains_module.shield_sync, "reconcile_quietly", lambda *a: synced.append(a))

    r = client.post("/api/onboarding/connect", headers=h,
                    json={"domain": "mine.waf-it-kku.online", "mode": "agent", "port": 3000})
    assert r.status_code == 200 and r.json()["verified"] is True
    origin_id = r.json()["origin_id"]
    r = client.post(f"/api/origins/{origin_id}/domains", headers=h, json={"domain_name": "two.waf-it-kku.online"})
    assert r.json()["auto_verified"] is True
    assert calls == ["mine.waf-it-kku.online", "two.waf-it-kku.online"]  # once each
    assert synced == []  # create_domain_record no longer syncs on its own


def test_review8_progress_checks_pending_domains_in_parallel(client, tenant, monkeypatch):
    import time as _time
    origin_id = _connect(client, tenant)
    for name in ("b.example.com", "c.example.com"):
        client.post(f"/api/origins/{origin_id}/domains", headers=tenant["headers"], json={"domain_name": name})

    def _slow(d, t):
        _time.sleep(0.4)
        return False
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", _slow)
    monkeypatch.setattr(site_connect, "current_dns", lambda d: {"cname": "", "a": []})
    onboarding_module._last_verify.clear()
    started = _time.monotonic()
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    elapsed = _time.monotonic() - started
    assert len(p["domains"]) == 3
    assert elapsed < 1.0, f"took {elapsed:.2f}s for 3 x 0.4s checks"


def test_review2_progress_reports_a_refused_route(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant, mode="direct", port=443, origin_address="203.0.113.10")
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(nss, "_failed_domains", {"shop.example.com": "nginx: [emerg] ..."})
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["domains"][0]["connection"]["status"] == "error"


def test_review3_editors_still_get_the_token_and_the_checks(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant)
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["domains"][0]["dns"]["instructions"]["txt_record"]["value"].startswith("waf-token-")
    assert p["can_edit"] is True
    assert p["can_mint_agent"] is True  # the owner


# --------------------------------------------------------------- re-review fixes
# Second code review (2026-10-11) of the fixed branch.

def test_rereview1_a_file_stays_unlive_while_its_reload_keeps_failing(container, monkeypatch):
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])

    def _refuse():
        raise RuntimeError("nginx reload failed")
    monkeypatch.setattr(nss.rule_mgr, "reload_nginx", _refuse)
    assert "reload_error" in reconcile_site_routes()   # run 1: written, reload refused
    assert "reload_error" in reconcile_site_routes()   # run 2: nothing new, retry refused
    assert nss.deployed_direct_domains() == set()       # never claimed live
    monkeypatch.setattr(nss.rule_mgr, "reload_nginx", lambda: None)
    reconcile_site_routes()                             # run 3: retry succeeds
    assert nss.deployed_direct_domains() == {"shop.example.com"}


def test_rereview2_an_unmanaged_file_for_a_desired_domain_is_not_overwritten(container):
    container.files["shop.example.com"] = "server { server_name shop.example.com; } # hand-written"
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])
    summary = reconcile_site_routes()
    assert container.files["shop.example.com"].endswith("# hand-written")
    assert summary["failed"] == ["shop.example.com"]
    assert container.reloads == 0


def test_rereview3_an_already_broken_config_blames_no_tenant(container, monkeypatch):
    _seed([DIRECT_IP], [{"id": uid("d1"), "origin_id": uid("o-direct"), "domain_name": "shop.example.com", "dns_verified": True}])

    def _broken():
        raise RuntimeError("nginx: [emerg] someone else's file")
    monkeypatch.setattr(nss.rule_mgr, "test_nginx", _broken)
    summary = reconcile_site_routes()
    assert "baseline_error" in summary
    assert summary["failed"] == []
    assert container.files == {}
    assert nss.failed_direct_domains() == {}


def test_rereview4_inspect_treats_our_own_hosts_as_already_connected(monkeypatch):
    monkeypatch.delenv("WAF_SELF_IPS", raising=False)
    monkeypatch.setattr(site_connect, "current_dns", lambda d: {"cname": "", "a": ["45.154.26.91"]})
    monkeypatch.setattr(site_connect, "resolve_a", lambda name: [])  # CNAME target answers nothing
    monkeypatch.setattr(site_connect, "probe_origin", lambda *a: pytest.fail("probed our own edge"))
    r = site_connect.inspect_domain("shop.example.com")
    assert r["already_points_to_platform"] is True


@pytest.mark.parametrize("ip", ["45.154.26.91", "172.18.0.250"])
def test_rereview4_9_probe_refuses_our_hosts_and_the_qa_private_allowlist(ip, monkeypatch):
    monkeypatch.delenv("WAF_SELF_IPS", raising=False)
    with pytest.raises(ValueError):
        site_connect.probe_origin(ip, "shop.example.com")


def test_rereview9_direct_mode_refuses_the_qa_private_allowlist():
    # validate_ip accepts ORIGIN_ALLOW_PRIVATE_CIDRS (qa-echo, 172.18.0.250).
    assert origin_service.validate_ip("172.18.0.250") is True
    assert nss.direct_upstream_allowed("172.18.0.250") is False


def test_rereview6_editing_a_direct_origin_keeps_the_address_rules(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant, mode="direct", port=443, origin_address="203.0.113.10")
    scheduled = []
    monkeypatch.setattr(domains_module, "schedule_site_reconcile", lambda: scheduled.append(1))
    r = client.put(f"/api/origins/{origin_id}", headers=tenant["headers"], json={"ip": "app.example.com"})
    assert r.status_code == 400
    r = client.put(f"/api/origins/{origin_id}", headers=tenant["headers"], json={"port": 80})
    assert r.status_code == 200
    [origin] = _origins()
    assert (origin["port"], origin["origin_scheme"]) == (80, "http")
    assert scheduled == [1]


def test_rereview6_progress_flags_an_unroutable_direct_address(client, tenant, monkeypatch):
    origin_id = _connect(client, tenant, mode="direct", port=443, origin_address="203.0.113.10")
    nss.db.update_origin(origin_id, {"ip": "app.example.com"})
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"]).json()
    assert p["domains"][0]["connection"]["status"] == "error"


def test_rereview8_editors_cannot_mint_agent_commands(client, tenant, register_user, auth_header):
    origin_id = _connect(client, tenant)
    editor = register_user(email="editor@example.com", username="editor_user")
    r = client.post(f"/api/origins/{origin_id}/editors", headers=tenant["headers"], json={"email": "editor@example.com"})
    assert r.status_code == 200, r.text
    p = client.get(f"/api/onboarding/progress/{origin_id}", headers=auth_header(editor["access_token"])).json()
    assert p["can_edit"] is True
    assert p["can_mint_agent"] is False


def test_rereview10_onboarding_status_does_not_depend_on_scan_order():
    origins = [{"id": uid("o1"), "created_at": "2026-10-09"}]
    a = {"id": "a", "origin_id": uid("o1"), "domain_name": "a.example.com", "dns_verified": False}
    b = {"id": "b", "origin_id": uid("o1"), "domain_name": "b.example.com", "dns_verified": True}
    s1 = onboarding_module.compute_onboarding_status(origins, [a, b])
    s2 = onboarding_module.compute_onboarding_status(origins, [b, a])
    assert s1 == s2
    assert s1["next_step"] == "done" and s1["resume_domain_id"] == "a"


def test_progress_probes_https_for_a_routed_domain_and_records_a_valid_certificate(client, tenant, monkeypatch):
    """The cert monitor runs every 6 hours; the page used to show a
    just-issued certificate as pending for hours."""
    monkeypatch.setenv("WAF_HTTPS_PROBE", "1")
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(site_connect, "current_dns",
                        lambda d: {"cname": "waf-token-x.cdn.waf-it-kku.online", "a": ["45.154.26.91"]})
    probed = []
    monkeypatch.setattr(onboarding_module, "_probe_https_via_edge",
                        lambda d: probed.append(d) or {"status": "ok", "not_after": "2027-01-19T00:00:00+00:00",
                                                       "issuer": "Let's Encrypt"})
    url = f"/api/onboarding/progress/{origin_id}"
    client.get(url, headers=tenant["headers"])          # schedules the probe
    [d] = client.get(url, headers=tenant["headers"]).json()["domains"]
    assert probed == ["shop.example.com"]               # once per minute, not per poll
    assert d["https"]["status"] == "active"


def test_progress_does_not_probe_https_while_the_name_points_elsewhere(client, tenant, monkeypatch):
    monkeypatch.setenv("WAF_HTTPS_PROBE", "1")
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(site_connect, "current_dns", lambda d: {"cname": "old.vercel-dns-017.com", "a": []})
    probed = []
    monkeypatch.setattr(onboarding_module, "_probe_https_via_edge", lambda d: probed.append(d) or {"status": "ok"})
    client.get(f"/api/onboarding/progress/{origin_id}", headers=tenant["headers"])
    assert probed == []


def test_a_failed_https_probe_leaves_the_status_pending(client, tenant, monkeypatch):
    monkeypatch.setenv("WAF_HTTPS_PROBE", "1")
    origin_id = _connect(client, tenant)
    monkeypatch.setattr(onboarding_module, "verify_domain_dns", lambda d, t: True)
    monkeypatch.setattr(site_connect, "current_dns",
                        lambda d: {"cname": "waf-token-x.cdn.waf-it-kku.online", "a": ["45.154.26.91"]})
    monkeypatch.setattr(onboarding_module, "_probe_https_via_edge", lambda d: {"status": "error", "error": "not yet"})
    url = f"/api/onboarding/progress/{origin_id}"
    client.get(url, headers=tenant["headers"])
    [d] = client.get(url, headers=tenant["headers"]).json()["domains"]
    assert d["https"]["status"] == "pending"
