"""
Scenario: 2026-09-21 -- Caddy's on-demand TLS `ask` directive pointed at
GET /api/health (which returns 200 unconditionally, ignoring the `domain`
query param Caddy sends) instead of this endpoint, which actually checks
domain ownership. Confirmed live: `curl .../api/health?domain=evil.example`
-> 200 (would-be cert issued for any domain pointed at our IP), while this
endpoint correctly returned 400 for the same input the whole time -- it
just was never wired up.

Fixing the Caddy wiring alone was not enough, though: this endpoint only
ever checked domains_table's dns_verified flag (the "bring your own
domain" CNAME+TXT flow) -- a domain claimed through either tunnel system
(cloudwaf's origins_table.tunnel_domains, or FRP's live-proxy-only signal,
since FRP's config-generator/create_tunnel_token never persist a
"verified" DB record at all) would still be rejected even after the Caddy
fix, silently blocking the wildcard-DNS "use our own subdomain" onboarding
path this platform already otherwise supports with zero DNS setup.

These tests cover all three recognized paths plus the original regression
guard (bare unregistered domain stays rejected).
"""
import asyncio

import pytest

import api.domains as domains_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_ssl_snapshot():
    """The allowed-domains snapshot is process-wide, cached for 30s --
    without resetting it, one test's fake DB/FRP state would leak into the
    next test's assertions."""
    domains_module._SSL_ALLOWED_SNAPSHOT = set()
    domains_module._SSL_SNAPSHOT_AT = 0.0
    yield
    domains_module._SSL_ALLOWED_SNAPSHOT = set()
    domains_module._SSL_SNAPSHOT_AT = 0.0


def test_unregistered_domain_is_still_rejected(monkeypatch):
    """Regression guard for the original P0: a domain with zero presence
    anywhere (no DNS-verified record, no tunnel_domains, no live FRP
    proxy) must never be allowed a certificate."""
    monkeypatch.setattr(domains_module.db.domains_table, "scan", lambda **kw: {"Items": []})
    monkeypatch.setattr(domains_module.db.origins_table, "scan", lambda **kw: {"Items": []})

    async def _no_proxies():
        return []

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _no_proxies)

    with pytest.raises(Exception) as exc_info:
        _run(domains_module.check_ssl_allowed(domain="evil-phishing-test.example"))
    assert getattr(exc_info.value, "status_code", None) == 400


def test_dns_verified_domain_is_allowed(monkeypatch):
    """The original "bring your own domain" path -- must keep working."""
    monkeypatch.setattr(
        domains_module.db.domains_table, "scan",
        lambda **kw: {"Items": [{"domain_name": "myapp.example.com", "dns_verified": True}]},
    )
    monkeypatch.setattr(domains_module.db.origins_table, "scan", lambda **kw: {"Items": []})

    async def _no_proxies():
        return []

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _no_proxies)

    result = _run(domains_module.check_ssl_allowed(domain="myapp.example.com"))
    assert result == {"status": "allowed", "domain": "myapp.example.com"}


def test_cloudwaf_tunnel_domain_is_allowed(monkeypatch):
    """New: a domain claimed via api/tunnel.py's issue_agent_token (stored
    in origins_table.tunnel_domains) must be allowed -- this table was
    never checked at all before this fix."""
    monkeypatch.setattr(domains_module.db.domains_table, "scan", lambda **kw: {"Items": []})
    monkeypatch.setattr(
        domains_module.db.origins_table, "scan",
        lambda **kw: {"Items": [{"id": "o1", "tunnel_domains": ["cloudwaf-app.waf-it-kku.online"]}]},
    )

    async def _no_proxies():
        return []

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _no_proxies)

    result = _run(domains_module.check_ssl_allowed(domain="cloudwaf-app.waf-it-kku.online"))
    assert result == {"status": "allowed", "domain": "cloudwaf-app.waf-it-kku.online"}


def test_live_frp_proxy_domain_is_allowed(monkeypatch):
    """New: a domain with a currently-online FRP proxy (the config-generator
    flow, which persists no DB "verified" record at all) must be allowed --
    this is the only real signal that flow's issued tokens are legitimate."""
    monkeypatch.setattr(domains_module.db.domains_table, "scan", lambda **kw: {"Items": []})
    monkeypatch.setattr(domains_module.db.origins_table, "scan", lambda **kw: {"Items": []})

    async def _fake_proxies():
        return [{
            "name": "frp-app-waf-it-kku-online",
            "status": "online",
            "conf": {"customDomains": ["frp-app.waf-it-kku.online"]},
        }]

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _fake_proxies)

    result = _run(domains_module.check_ssl_allowed(domain="frp-app.waf-it-kku.online"))
    assert result == {"status": "allowed", "domain": "frp-app.waf-it-kku.online"}


def test_offline_frp_proxy_domain_is_not_allowed(monkeypatch):
    """An FRP proxy that exists in the dashboard but is offline right now
    must not grant a cert -- only a currently-live tunnel counts as real
    evidence of legitimate ownership."""
    monkeypatch.setattr(domains_module.db.domains_table, "scan", lambda **kw: {"Items": []})
    monkeypatch.setattr(domains_module.db.origins_table, "scan", lambda **kw: {"Items": []})

    async def _fake_proxies():
        return [{
            "name": "frp-app-waf-it-kku-online",
            "status": "offline",
            "conf": {"customDomains": ["frp-app.waf-it-kku.online"]},
        }]

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _fake_proxies)

    with pytest.raises(Exception) as exc_info:
        _run(domains_module.check_ssl_allowed(domain="frp-app.waf-it-kku.online"))
    assert getattr(exc_info.value, "status_code", None) == 400


def test_a_transient_frp_dashboard_failure_does_not_reject_everything(monkeypatch):
    """get_live_proxies() failing (FRP dashboard unreachable) must degrade
    to "no FRP-sourced domains this cycle", not crash the whole allowed-set
    refresh and lock out every domain including DB-verified ones."""
    monkeypatch.setattr(
        domains_module.db.domains_table, "scan",
        lambda **kw: {"Items": [{"domain_name": "myapp.example.com", "dns_verified": True}]},
    )
    monkeypatch.setattr(domains_module.db.origins_table, "scan", lambda **kw: {"Items": []})

    async def _broken_proxies():
        raise Exception("FRP dashboard unreachable")

    import services.origin_service as origin_service_module
    monkeypatch.setattr(origin_service_module, "get_live_proxies", _broken_proxies)

    result = _run(domains_module.check_ssl_allowed(domain="myapp.example.com"))
    assert result == {"status": "allowed", "domain": "myapp.example.com"}
