"""Platform admins (the support team) see a tenant's logs and alerts only while
that tenant's origin has an active support grant (docs/tickets/support-access.md)."""
import pytest

import services.tenant_service as ts
from api import ai_summary


@pytest.fixture()
def scope(monkeypatch):
    state = {"tenant": {"shop.com", "blog.com"}, "granted": set(),
             "tids": {"o-shop", "o-blog"}, "gids": set()}
    monkeypatch.setattr(ts, "admin_log_scope",
                        lambda: (state["tenant"], state["granted"], state["tids"], state["gids"]))
    return state


def test_admin_all_excludes_tenant_hosts_without_grant(scope):
    f = ts.build_tenant_origin_filter("ALL", [], True)
    assert f.startswith("(host NOT IN (") and "'shop.com'" in f and "'blog.com'" in f


def test_admin_all_includes_granted_tenant(scope):
    scope["granted"] = {"shop.com"}
    f = ts.build_tenant_origin_filter("ALL", [], True)
    assert "'shop.com'" not in f and "'blog.com'" in f


def test_admin_all_unrestricted_when_no_tenants(scope):
    scope["tenant"] = set()
    assert ts.build_tenant_origin_filter("ALL", [], True) == ""


def test_admin_specific_origin_needs_grant(scope):
    assert ts.build_tenant_origin_filter("shop.com", [], True) == "1=0"
    scope["granted"] = {"shop.com"}
    assert ts.build_tenant_origin_filter("shop.com", [], True) == "(host = 'shop.com')"


def test_admin_may_read_non_tenant_host(scope):
    assert ts.build_tenant_origin_filter("waf-it-kku.online", [], True) == "(host = 'waf-it-kku.online')"


def test_admin_scope_fails_closed(monkeypatch):
    def boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(ts, "admin_log_scope", boom)
    assert ts.build_tenant_origin_filter("ALL", [], True) == "1=0"


def test_tenant_filter_unchanged_for_non_admin(scope):
    assert ts.build_tenant_origin_filter("ALL", ["mine.com"], False) == "((host = 'mine.com'))"
    assert ts.build_tenant_origin_filter("shop.com", ["mine.com"], False) == "1=0"


def test_admin_alerts_follow_grants(scope, monkeypatch):
    alerts = [{"alert_id": "1", "origin_id": "o-shop"}, {"alert_id": "2", "origin_id": "o-blog"},
              {"alert_id": "3", "origin_id": "unattributed"}, {"alert_id": "4", "origin_id": None}]
    monkeypatch.setattr(ai_summary.db, "get_all_alerts", lambda max_items=2000: alerts)
    admin = {"role": "admin", "user_id": "a"}
    assert {a["alert_id"] for a in ai_summary._visible_alerts_for_user(admin)} == {"3", "4"}
    scope["gids"] = {"o-shop"}
    assert {a["alert_id"] for a in ai_summary._visible_alerts_for_user(admin)} == {"1", "3", "4"}


def test_admin_alerts_fail_closed(monkeypatch):
    def boom():
        raise RuntimeError("db down")
    monkeypatch.setattr(ts, "admin_log_scope", boom)
    assert ai_summary._visible_alerts_for_user({"role": "admin", "user_id": "a"}) == []


def test_admin_origin_id_scopes_to_that_origins_hosts(scope, monkeypatch):
    oid = "6f1c0d2e-0000-4000-8000-000000000001"
    monkeypatch.setattr(ts, "_origin_scope_hosts", lambda o: ["shop.com", "www.shop.com"] if o == oid else None)
    scope["tenant"] = {"shop.com", "www.shop.com", "blog.com"}
    assert ts.build_tenant_origin_filter(oid, [], True) == "1=0"  # no support grant yet
    scope["granted"] = {"shop.com", "www.shop.com"}
    assert ts.build_tenant_origin_filter(oid, [], True) == "((host = 'shop.com') OR (host = 'www.shop.com'))"
