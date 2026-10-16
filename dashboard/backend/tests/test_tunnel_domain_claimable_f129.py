"""F-129 regression: _assert_domain_claimable must stop a non-admin from claiming
an unregistered host at/under the platform apex (*.waf-it-kku.online), while
leaving legitimate flows (admin, re-claim of a domain you own) working. Covers
single- AND multi-label platform subdomains.

P3.2 (N4) tightened it: a tunnel token is issued only for a domain that an
active origin of the caller has DNS-verified (an admin: any verified domain,
or a platform subdomain). An external domain nobody verified is refused too."""
import pytest
from fastapi import HTTPException
from api import tunnels


@pytest.fixture
def no_domains(monkeypatch):
    """Nothing registered yet."""
    monkeypatch.setattr(tunnels.db, "get_verified_domain", lambda *a, **k: None)
    monkeypatch.setattr(tunnels.db, "get_origin_by_id", lambda *_a, **_k: None)


def _registered_to(monkeypatch, owner_user_id, status="active", host="shop.waf-it-kku.online"):
    """One verified domain record whose origin belongs to owner_user_id."""
    monkeypatch.setattr(tunnels.db, "get_verified_domain",
                        lambda name, *a, **k: {"domain_name": host, "origin_id": "o1"} if name == host else None)
    monkeypatch.setattr(tunnels.db, "get_origin_by_id",
                        lambda *_a, **_k: {"admin_user_id": owner_user_id, "status": status})


VIEWER = {"user_id": "u-viewer", "role": "viewer"}
ADMIN = {"user_id": "u-admin", "role": "admin"}


def test_unverified_external_domain_is_refused(no_domains):
    # P3.2: nobody has verified myshop.com, so nobody gets a token for it
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("myshop.com", VIEWER)
    assert e.value.status_code == 403
    assert "verify" in e.value.detail.lower()


def test_own_verified_external_domain_is_allowed(monkeypatch):
    _registered_to(monkeypatch, VIEWER["user_id"], host="myshop.com")
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
    # viewer already owns this (verified) platform subdomain -> may re-mint a token for it
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


def test_domain_of_an_archived_origin_is_refused(monkeypatch):
    _registered_to(monkeypatch, VIEWER["user_id"], status="archived", host="myshop.com")
    with pytest.raises(HTTPException) as e:
        tunnels._assert_domain_claimable("myshop.com", VIEWER)
    assert e.value.status_code == 403


@pytest.mark.parametrize("spelling", ["MyShop.com", "myshop.com.", " myshop.com "])
def test_every_spelling_of_a_domain_gets_the_same_answer(monkeypatch, spelling):
    """P3.3 (N5): one canonical form, so the check cannot differ by spelling."""
    _registered_to(monkeypatch, VIEWER["user_id"], host="myshop.com")
    tunnels._assert_domain_claimable(tunnels._canonical_or_422(spelling), VIEWER)  # no raise
    _registered_to(monkeypatch, "someone-else", host="myshop.com")
    with pytest.raises(HTTPException):
        tunnels._assert_domain_claimable(tunnels._canonical_or_422(spelling), VIEWER)
