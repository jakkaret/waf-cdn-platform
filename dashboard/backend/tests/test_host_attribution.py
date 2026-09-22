"""
Scenario: a tenant's analytics/logs no longer inherit another tenant's
traffic just because both run the same kind of app.

Before 2026-09-22, access_logs had no column saying which origin a request
belonged to, so every tenant filter guessed from the URL: an origin whose
name contained "dvwa" matched `url LIKE '%.php%'`, i.e. any PHP request in
the table, from any tenant. Two tenants both running DVWA were literally
indistinguishable. Reported live: a viewer granted one origin saw
system-wide totals.

ModSecurity's audit log had carried the real Host header all along
(log_forward.normalize_modsec) and nginx now logs $host too; the value was
dropped at insert only because no column held it. These tests lock in the
three halves of the fix: the value is normalised on the way in, the SQL
matches it exactly on the way out, and the old keyword guess is confined
to rows written before the column existed (host = '') so it can never
again widen a live query.
"""
from services.clickhouse_service import normalize_host
from services.tenant_service import build_domain_pattern_sql, build_tenant_origin_filter


# --- ingest side -----------------------------------------------------


def test_normalize_host_strips_port_and_lowercases():
    # A Host header legitimately carries the port; waf_domains stores the
    # bare name, and the two have to compare equal.
    assert normalize_host("DVWA.Waf-It-KKU.online:8080") == "dvwa.waf-it-kku.online"


def test_normalize_host_strips_root_label_dot():
    assert normalize_host("juice.waf-it-kku.online.") == "juice.waf-it-kku.online"


def test_normalize_host_handles_ipv6_literal():
    assert normalize_host("[2001:db8::1]:443") == "2001:db8::1"


def test_normalize_host_empty_when_absent():
    # normalize_modsec yields None when the audit entry had no Host header,
    # and the nginx path predates the log_format change; both must land as
    # '' so the legacy branch below is what matches those rows.
    assert normalize_host(None) == ""
    assert normalize_host("   ") == ""


# --- query side ------------------------------------------------------


def test_exact_host_match_is_preferred():
    sql = build_domain_pattern_sql("dvwa.waf-it-kku.online")
    assert "host = 'dvwa.waf-it-kku.online'" in sql


def test_legacy_keyword_guess_only_applies_to_hostless_rows():
    # The '.php' sweep is what leaked across tenants. It may still appear
    # (old rows need it) but never without the host = '' guard in front.
    sql = build_domain_pattern_sql("dvwa.waf-it-kku.online")
    assert "%.php%" in sql, "legacy fallback should still cover pre-column rows"
    php_clause = sql.split("%.php%")[0]
    assert "host = ''" in php_clause, (
        "the keyword guess must be gated on host = '' -- ungated, it matches "
        "every tenant's PHP traffic, which is the leak this fix exists for"
    )


def test_host_value_is_escaped_into_the_literal():
    # Same unparameterised f-string interpolation the rest of this module
    # uses, so the quote has to be neutralised rather than closing early.
    sql = build_domain_pattern_sql("evil'.example.com")
    assert "evil\\'.example.com" in sql


def test_two_tenants_on_the_same_app_get_different_filters():
    # The property the old keyword matcher could not express at all: both
    # of these would previously collapse to the identical '%dvwa%' /
    # '%.php%' clause and each tenant would read the other's traffic.
    a = build_tenant_origin_filter("ALL", ["dvwa.alice.example"], is_admin=False)
    b = build_tenant_origin_filter("ALL", ["dvwa.bob.example"], is_admin=False)
    assert a != b
    assert "host = 'dvwa.alice.example'" in a
    assert "host = 'dvwa.bob.example'" in b
    assert "dvwa.bob.example" not in a


def test_non_admin_with_no_domains_still_fails_closed():
    # Unchanged behaviour, re-asserted because the fix rewrote the function
    # that decides it: no registered origin means no rows, never all rows.
    assert build_tenant_origin_filter("ALL", [], is_admin=False) == "1=0"


def test_requesting_another_tenants_origin_still_forbidden():
    sql = build_tenant_origin_filter(
        "dvwa.bob.example", ["dvwa.alice.example"], is_admin=False
    )
    assert sql == "1=0"


def test_admin_all_scope_unrestricted():
    assert build_tenant_origin_filter("ALL", ["anything"], is_admin=True) == ""
