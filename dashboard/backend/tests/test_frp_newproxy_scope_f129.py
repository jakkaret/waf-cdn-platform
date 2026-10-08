"""F-129 residual: frp-hook NewProxy must authorize a binding only when EVERY
requested custom domain equals the token's single scoped domain and no subdomain
routing is used. Previously it compared only custom_domains[0], so a token for
one's own domain could smuggle a second vhost (e.g. a platform-apex host)."""
import pytest
from api import tunnels


@pytest.fixture
def jwt_for_myshop(monkeypatch):
    # every request in these tests presents a valid JWT scoped to myshop.com
    monkeypatch.setattr(tunnels, "_resolve_frp_identity",
                        lambda *a, **k: ("jwt", {"domain": "myshop.com", "user_id": "u1"}))


def _newproxy(custom_domains, subdomain=""):
    return {"op": "NewProxy", "content": {
        "proxy_name": "p1",
        "custom_domains": custom_domains,
        "subdomain": subdomain,
        "metas": {"token": "x"},
    }}


@pytest.mark.asyncio
async def test_single_own_domain_authorized(jwt_for_myshop):
    r = await tunnels.frp_webhook_gatekeeper(_newproxy(["myshop.com"]))
    assert r["reject"] is False


@pytest.mark.asyncio
async def test_smuggled_platform_host_rejected(jwt_for_myshop):
    r = await tunnels.frp_webhook_gatekeeper(_newproxy(["myshop.com", "evil.waf-it-kku.online"]))
    assert r["reject"] is True


@pytest.mark.asyncio
async def test_cross_domain_only_rejected(jwt_for_myshop):
    r = await tunnels.frp_webhook_gatekeeper(_newproxy(["evil.waf-it-kku.online"]))
    assert r["reject"] is True


@pytest.mark.asyncio
async def test_subdomain_routing_rejected(jwt_for_myshop):
    r = await tunnels.frp_webhook_gatekeeper(_newproxy(["myshop.com"], subdomain="victim"))
    assert r["reject"] is True


@pytest.mark.asyncio
async def test_reserved_host_at_index_1_rejected(jwt_for_myshop):
    r = await tunnels.frp_webhook_gatekeeper(_newproxy(["myshop.com", "api.waf-it-kku.online"]))
    assert r["reject"] is True
