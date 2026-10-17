"""Re-audit 2026-10-17: the NewProxy hook binds only an http(s) vhost, refuses
a proxy that names no domain, and never moves a proxy name recorded for one
domain to the holder of a token for another domain."""
import pytest
from api import tunnels
from services.dynamodb_service import DynamoDBService
from tests.helpers.seed import make_tunnel_owner


def _jwt(monkeypatch, domain, owner):
    monkeypatch.setattr(tunnels, "_resolve_frp_identity",
                        lambda *a, **k: ("jwt", {"domain": domain, "user_id": owner}))


def _newproxy(name, domains, ptype=None, user="T"):
    c = {"proxy_name": name, "custom_domains": domains, "metas": {"token": "x"}, "user": {"user": user}}
    if ptype is not None:
        c["proxy_type"] = ptype
    return {"op": "NewProxy", "content": c}


@pytest.mark.asyncio
@pytest.mark.parametrize("ptype", ["tcp", "udp", "stcp", "xtcp", "tcpmux"])
async def test_non_http_proxy_rejected(monkeypatch, ptype):
    _jwt(monkeypatch, "myshop.com", make_tunnel_owner("myshop.com"))
    r = await tunnels.frp_webhook_gatekeeper(_newproxy("myshop.com", [], ptype))
    assert r["reject"] is True


@pytest.mark.asyncio
async def test_http_proxy_still_allowed(monkeypatch):
    _jwt(monkeypatch, "myshop.com", make_tunnel_owner("myshop.com"))
    r = await tunnels.frp_webhook_gatekeeper(_newproxy("myshop.com", ["myshop.com"], "http"))
    assert r["reject"] is False


@pytest.mark.asyncio
async def test_proxy_with_no_domain_rejected():
    r = await tunnels.frp_webhook_gatekeeper(_newproxy("", []))
    assert r["reject"] is True


@pytest.mark.asyncio
async def test_other_tenant_cannot_take_over_proxy_name(monkeypatch):
    victim = make_tunnel_owner("victim.com")
    attacker = make_tunnel_owner("attacker.com")
    _jwt(monkeypatch, "victim.com", victim)
    assert (await tunnels.frp_webhook_gatekeeper(_newproxy("T.victim.com", ["victim.com"])))["reject"] is False
    _jwt(monkeypatch, "attacker.com", attacker)
    r = await tunnels.frp_webhook_gatekeeper(_newproxy("T.victim.com", ["attacker.com"]))
    assert r["reject"] is True
    assert DynamoDBService().get_proxy_owner("T.victim.com") == str(victim)


@pytest.mark.asyncio
async def test_other_tenant_cannot_squat_victims_name_first(monkeypatch):
    """The name must be derived from the token's own domain, so an attacker
    cannot register the victim's predictable name before the victim connects."""
    victim = make_tunnel_owner("victim2.com")
    attacker = make_tunnel_owner("attacker2.com")
    _jwt(monkeypatch, "attacker2.com", attacker)
    r = await tunnels.frp_webhook_gatekeeper(_newproxy("T.victim2.com", ["attacker2.com"]))
    assert r["reject"] is True
    assert DynamoDBService().get_proxy_owner("T.victim2.com") is None
    _jwt(monkeypatch, "victim2.com", victim)
    assert (await tunnels.frp_webhook_gatekeeper(_newproxy("T.victim2.com", ["victim2.com"])))["reject"] is False


@pytest.mark.parametrize("name,user,ok", [
    ("shop.example", "", True), ("tok.shop.example", "tok", True),
    ("tok.shop.example", "", False),            # prefix only when it is the login user
    ("x.shop.example", "tok", False),           # another subdomain is not this domain
    ("shop-example", "", False),                # old lossy dashed form refused
    ("p1", "", False), ("shop.example.evil", "", False), ("myshop.example", "", False)])
def test_proxy_name_matches_domain(name, user, ok):
    assert tunnels._proxy_name_matches_domain(name, "shop.example", user) is ok


@pytest.mark.asyncio
async def test_lookalike_domain_cannot_take_the_name(monkeypatch):
    """my-shop.com and my.shop.com no longer share a proxy name."""
    a = make_tunnel_owner("my.shop.com")
    b = make_tunnel_owner("my-shop.com")
    _jwt(monkeypatch, "my-shop.com", b)
    assert (await tunnels.frp_webhook_gatekeeper(_newproxy("T.my-shop.com", ["my-shop.com"])))["reject"] is False
    _jwt(monkeypatch, "my.shop.com", a)
    assert (await tunnels.frp_webhook_gatekeeper(_newproxy("T.my.shop.com", ["my.shop.com"])))["reject"] is False


def test_same_domain_refreshes_owner():
    a = make_tunnel_owner("shop.example")
    db = DynamoDBService()
    assert db.set_proxy_owner("n1", a, "shop.example") is True
    assert db.set_proxy_owner("n1", a, "shop.example") is True
    assert db.set_proxy_owner("n1", a, "other.example") is False
    assert db.get_proxy_owner("n1") == str(a)
