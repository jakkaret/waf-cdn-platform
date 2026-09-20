"""
Scenario: 2026-09-21 -- format_domain() (api/domains.py, feeds
GET /api/origins/{id}/domains, which OriginDetail.tsx's "SSL Certificates"
tab renders directly) read `domain_data.get("ssl_status", "none")` -- a
field never written anywhere in the codebase. Combined with the frontend's
own `domain.ssl_status || 'ACTIVE'` fallback, every domain rendered as a
hardcoded "ACTIVE" regardless of whether it had a certificate at all.
services/ssl_cert_monitor.py now writes real, periodically-probed records
into waf_ssl_certs; these tests cover format_domain() actually reading them.
"""
import api.domains as domains_module


def test_a_domain_with_a_healthy_probed_certificate_reports_active_with_real_fields():
    # waf_ssl_certs' real key schema is HASH="id" -- see
    # services/ssl_cert_monitor.py's _persist_cert_record.
    domains_module.db.ssl_certs_table.put_item(Item={
        "id": "healthy.example.com",
        "domain": "healthy.example.com",
        "status": "ok",
        "not_after": "2026-12-25T00:00:00+00:00",
        "issuer": "Let's Encrypt",
        "days_remaining": 60,
        "checked_at": "2026-11-01T00:00:00+00:00",
    })

    result = domains_module.format_domain({
        "id": "d1", "domain_name": "healthy.example.com", "dns_verified": True,
    })

    assert result["ssl_status"] == "active"
    assert result["ssl_expires_at"] == "2026-12-25T00:00:00+00:00"
    assert result["ssl_issuer"] == "Let's Encrypt"
    assert result["ssl_days_remaining"] == 60


def test_a_domain_whose_probe_failed_reports_error_not_a_fake_active():
    domains_module.db.ssl_certs_table.put_item(Item={
        "id": "broken.example.com",
        "domain": "broken.example.com",
        "status": "error",
        "error": "connection refused",
        "days_remaining": None,
        "checked_at": "2026-11-01T00:00:00+00:00",
    })

    result = domains_module.format_domain({
        "id": "d2", "domain_name": "broken.example.com", "dns_verified": True,
    })

    assert result["ssl_status"] == "error"
    assert result["ssl_expires_at"] is None


def test_a_domain_the_monitor_has_not_reached_yet_reports_pending_not_a_fake_active():
    # Regression guard for the exact original bug: no waf_ssl_certs row at
    # all must never silently read as "active"/"ACTIVE".
    result = domains_module.format_domain({
        "id": "d3", "domain_name": "never-checked.example.com", "dns_verified": True,
    })

    assert result["ssl_status"] == "pending"
    assert result["ssl_expires_at"] is None
    assert result["ssl_issuer"] is None
    assert result["ssl_days_remaining"] is None
