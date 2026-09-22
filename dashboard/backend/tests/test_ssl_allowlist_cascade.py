"""
Scenario: archiving an origin stops its domains getting TLS certificates.

delete_origin() is a soft delete -- it sets status=archived on the origin
row and nothing else. waf_domains rows have no status field of their own
and are never touched, so the domain keeps existing with
dns_verified=True. _load_ssl_allowed_from_db() read every verified domain
and every origin's tunnel_domains with no reference to the parent
origin's status, which meant a resource the owner had removed could still
obtain and renew certificates indefinitely, for as long as the row sat in
the table.

Tenant scoping already draws this line -- tenant_service's
get_user_origins_and_domains() filters to active origins before it
collects any domain names. These tests pin the same rule for cert
issuance.
"""
import api.domains as domains_module


class _FakeTable:
    def __init__(self, rows):
        self.rows = rows

    def scan(self, **_kwargs):
        return {"Items": self.rows}


def _install(monkeypatch, origins, domains):
    fake_db = type("_FakeDb", (), {})()
    fake_db.origins_table = _FakeTable(origins)
    fake_db.domains_table = _FakeTable(domains)
    monkeypatch.setattr(domains_module, "db", fake_db)


def test_archived_origin_domain_is_not_allowed_a_certificate(monkeypatch):
    _install(
        monkeypatch,
        origins=[
            {"id": "o-live", "status": "active"},
            {"id": "o-gone", "status": "archived"},
        ],
        domains=[
            {"origin_id": "o-live", "domain_name": "live.example.com", "dns_verified": True},
            {"origin_id": "o-gone", "domain_name": "gone.example.com", "dns_verified": True},
        ],
    )

    allowed = domains_module._load_ssl_allowed_from_db()

    assert "live.example.com" in allowed
    assert "gone.example.com" not in allowed


def test_archived_origin_tunnel_domains_are_not_allowed_either(monkeypatch):
    # tunnel_domains live on the origin row itself rather than in
    # waf_domains, so they need the same check applied separately.
    _install(
        monkeypatch,
        origins=[
            {"id": "o-live", "status": "active", "tunnel_domains": ["t-live.example.com"]},
            {"id": "o-gone", "status": "archived", "tunnel_domains": ["t-gone.example.com"]},
        ],
        domains=[],
    )

    allowed = domains_module._load_ssl_allowed_from_db()

    assert allowed == {"t-live.example.com"}


def test_deleted_status_is_treated_the_same_as_archived(monkeypatch):
    _install(
        monkeypatch,
        origins=[{"id": "o-del", "status": "deleted"}],
        domains=[{"origin_id": "o-del", "domain_name": "del.example.com", "dns_verified": True}],
    )

    assert domains_module._load_ssl_allowed_from_db() == set()


def test_unverified_domain_of_a_live_origin_is_still_excluded(monkeypatch):
    # Pre-existing rule, re-asserted so the new origin-status filter cannot
    # accidentally become the only thing gating issuance.
    _install(
        monkeypatch,
        origins=[{"id": "o-live", "status": "active"}],
        domains=[
            {"origin_id": "o-live", "domain_name": "pending.example.com", "dns_verified": False},
        ],
    )

    assert domains_module._load_ssl_allowed_from_db() == set()


def test_origin_with_no_status_field_is_treated_as_live(monkeypatch):
    # Older origin rows predate the status field; absent must not mean
    # archived, or existing certificates would stop renewing.
    _install(
        monkeypatch,
        origins=[{"id": "o-old"}],
        domains=[{"origin_id": "o-old", "domain_name": "old.example.com", "dns_verified": True}],
    )

    assert domains_module._load_ssl_allowed_from_db() == {"old.example.com"}
