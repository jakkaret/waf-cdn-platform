"""F-129 regression (record-creation gate + string logic). The real fix lives in
api.domains: a non-admin must not be able to CREATE (or auto-verify) a domain
record under the platform apex, because a self-created record was enough to pass
the _assert_domain_claimable ownership check and mint a tunnel token. Also pins
the is_platform_subdomain string normalization."""
import pytest
from fastapi import HTTPException
from services.dns_service import is_platform_subdomain
from api import domains


# ---- is_platform_subdomain string logic ----
@pytest.mark.parametrize("host,expected", [
    ("evil.waf-it-kku.online", True),
    ("a.b.waf-it-kku.online", True),          # deep subdomain still routed to tunnel
    ("waf-it-kku.online", True),              # apex
    ("  EVIL.WAF-IT-KKU.ONLINE  ", True),     # case + surrounding whitespace
    ("evil.waf-it-kku.online.", True),        # FQDN trailing dot must not evade
    ("myshop.com", False),                    # a tenant's own external domain
    ("waf-it-kku.online.evil.com", False),    # lookalike: different apex, attacker-owned
    ("xwaf-it-kku.online", False),            # not a subdomain of the apex
])
def test_is_platform_subdomain(host, expected):
    assert is_platform_subdomain(host) is expected


# ---- api.domains record-creation gate ----
VIEWER = {"user_id": "u-viewer", "role": "viewer"}
ADMIN = {"user_id": "u-admin", "role": "admin"}


def test_guard_blocks_non_admin_platform_subdomain():
    for host in ("evil.waf-it-kku.online", "a.b.waf-it-kku.online"):
        with pytest.raises(HTTPException) as e:
            domains._assert_platform_subdomain_allowed(host, VIEWER)
        assert e.value.status_code == 403


def test_guard_allows_admin_platform_subdomain():
    domains._assert_platform_subdomain_allowed("labtest.waf-it-kku.online", ADMIN)  # no raise


def test_guard_allows_non_admin_external_domain():
    domains._assert_platform_subdomain_allowed("myshop.com", VIEWER)  # no raise
