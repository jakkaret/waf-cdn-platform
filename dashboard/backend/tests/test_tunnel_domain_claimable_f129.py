"""F-129 regression: _assert_domain_claimable must stop a non-admin from claiming
an unregistered host at/under the platform apex (*.waf-it-kku.online), while
leaving legitimate flows (own external domain, admin, re-claim of a domain you
already own) working. Covers single- AND multi-label platform subdomains."""
import pytest
from fastapi import HTTPException
from api import tunnels


@pytest.fixture
def no_domains(monkeypatch):
    """domains_table.scan() -> empty (nothing registered yet)."""
    class _T:
        def scan(self, *a, **k):
            return {"Items": []}
    monkeypatch.setattr(tunnels.db, "domains_table", _T())
    monkeypatch.setattr(tunnels.db, "get_origin_by_id", lambda *_a, **_k: None)


def _registered_to(monkeypatch, owner_user_id):
    """One domain record whose origin belongs to owner_user_id."""
    class _T:
        def scan(self, *a, **k):
            return {"Items": [{"domain_name": "shop.waf-it-kku.online", "origin_id": "o1"}]}
    monkeypatch.setattr(tunnels.db, "domains_table", _T())
    monkeypatch.setattr(tunnels.db, "get_origin_by_id",
                        lambda *_a, **_k: {"admin_user_id": owner_user_id})


VIEWER = {"user_id": "u-viewer", "role": "viewer"}
ADMIN = {"user_id": "u-admin", "role": "admin"}


def test_external_domain_non_admin_allowed(no_domains):
    # a tenant's OWN domain (not under the platform apex) is claimable
    tunnels._assert_domain_claimable("myshop.com", VIEWER)  # no raise


def test_platform_subdomain_single_label_blocked(no_domains):
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("evil.waf-it-kku.online", VIEWER)
    assert e.value.status_code == 403
    assert "operator" in e.value.detail.lower()


def test_platform_subdomain_deep_label_blocked(no_domains):
    # the key improvement: a nested host is routed to the tunnel too, so it must
    # also be blocked (is_claimable_own_wildcard_subdomain alone would miss it)
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("a.b.waf-it-kku.online", VIEWER)
    assert e.value.status_code == 403


def test_platform_subdomain_admin_allowed(no_domains):
    tunnels._assert_domain_claimable("labtest.waf-it-kku.online", ADMIN)  # no raise


def test_platform_subdomain_owner_can_reclaim(monkeypatch):
    # viewer already owns this platform subdomain -> may re-mint a token for it
    _registered_to(monkeypatch, VIEWER["user_id"])
    tunnels._assert_domain_claimable("shop.waf-it-kku.online", VIEWER)  # no raise


def test_reserved_subdomain_rejected(no_domains):
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("api.waf-it-kku.online", VIEWER)
    assert e.value.status_code == 400


def test_domain_owned_by_other_blocked(monkeypatch):
    _registered_to(monkeypatch, "someone-else")
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("shop.waf-it-kku.online", VIEWER)
    assert e.value.status_code == 403
    assert "another account" in e.value.detail.lower()


def test_admin_may_claim_other_owned(monkeypatch):
    _registered_to(monkeypatch, "someone-else")
    tunnels._assert_domain_claimable("shop.waf-it-kku.online", ADMIN)  # admin override, no raise
