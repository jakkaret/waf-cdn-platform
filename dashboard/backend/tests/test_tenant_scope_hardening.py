"""Regression guards for the 2026-09-30 tenant-scope hardening.

Two related holes let one tenant read another's data:

  1. tenant_service.get_user_origins_and_domains / ai_summary._build_origin_scope_sql
     built their ClickHouse scope keywords from an origin's *self-typed* `ip`
     and the `(domain)` inside its `label`, plus *unverified* domain rows.
     Those keywords decide which `host` rows a tenant sees, so typing another
     tenant's hostname into your own origin exposed their logs/analytics/alerts.
     Fixed: verified_scope_keywords() trusts only DNS-verified domains and
     tunnel_domains (the two channels that actually carry that tenant's traffic).

  2. origin_service.validate_ip accepted `localhost` and any private/loopback/
     link-local IP as an origin address (SSRF surface for the nginx upstream).
     Fixed: literal IPs must be public unless allowlisted via
     ORIGIN_ALLOW_PRIVATE_CIDRS.
"""
import ipaddress

from services.tenant_service import verified_scope_keywords
import services.origin_service as origin_service


# ---------------------------------------------------- verified_scope_keywords

def test_self_typed_ip_and_label_never_become_scope_keywords():
    origins = [{
        "id": "o1",
        "ip": "victim-tenant.example.com",              # attacker types a victim host
        "label": "totally mine (victim-tenant.example.com)",
    }]
    domain_rows = []
    assert verified_scope_keywords(origins, domain_rows) == set()


def test_unverified_domain_row_is_excluded():
    origins = [{"id": "o1"}]
    domain_rows = [{"domain_name": "claimed.example.com", "dns_verified": False}]
    assert verified_scope_keywords(origins, domain_rows) == set()
    # missing flag defaults to not-verified
    assert verified_scope_keywords(origins, [{"domain_name": "x.example.com"}]) == set()


def test_verified_domain_and_tunnel_domain_are_included():
    origins = [{"id": "o1", "tunnel_domains": ["tun.example.com", ""]}]
    domain_rows = [
        {"domain_name": "Verified.Example.com", "dns_verified": True},
        {"domain_name": "nope.example.com", "dns_verified": False},
    ]
    assert verified_scope_keywords(origins, domain_rows) == {
        "verified.example.com", "tun.example.com",
    }


def test_none_inputs_are_safe():
    assert verified_scope_keywords(None, None) == set()


# --------------------------------------------------------------- validate_ip

def test_public_ip_and_hostname_still_valid():
    assert origin_service.validate_ip("203.0.113.10") is True
    assert origin_service.validate_ip("app.customer.com") is True


def test_loopback_private_linklocal_and_localhost_rejected(monkeypatch):
    # No allowlist for this assertion.
    monkeypatch.setattr(origin_service, "_ALLOWED_PRIVATE_NETS", [])
    for bad in ("127.0.0.1", "::1", "localhost", "10.0.0.5", "192.168.1.1",
                "172.16.0.9", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
        assert origin_service.validate_ip(bad) is False, f"{bad} must be rejected"


def test_allowlisted_private_cidr_is_accepted(monkeypatch):
    monkeypatch.setattr(
        origin_service, "_ALLOWED_PRIVATE_NETS", [ipaddress.ip_network("172.18.0.250/32")]
    )
    assert origin_service.validate_ip("172.18.0.250") is True
    assert origin_service.validate_ip("172.18.0.251") is False  # outside the /32
