"""Phase 5: global IP rules and rate-limit rules on PostgreSQL (were SQLite)."""
import time

import pytest

from tests import pg_harness

pytestmark = [pytest.mark.pg,
              pytest.mark.skipif(not pg_harness.enabled(), reason="TEST_DATABASE_URL not set")]


@pytest.fixture()
def ip_service(monkeypatch, tmp_path):
    from db import pool
    import services.ip_rule_service as m
    monkeypatch.setenv("DATA_BACKEND", "postgres")
    pool.close_pool()
    for name in ("BLOCKLIST_TXT", "WHITELIST_TXT", "BLOCKLIST_CONF", "WHITELIST_CONF"):
        monkeypatch.setattr(m, name, tmp_path / getattr(m, name).name)
    svc = m.IPRuleService()
    monkeypatch.setattr(svc, "_reload_nginx", lambda: True)
    yield svc, tmp_path
    pool.close_pool()


def test_creating_the_service_touches_no_database(monkeypatch):
    import services.ip_rule_service as m
    import services.rate_limit_service as r
    monkeypatch.setenv("DATA_BACKEND", "postgres")
    monkeypatch.setenv("DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
    from db import pool
    pool.close_pool()
    m.IPRuleService()          # no connection attempted
    r.RateLimitService()
    pool.close_pool()


def test_add_again_updates_the_same_row(ip_service):
    svc, _ = ip_service
    svc.add_rule("10.0.0.0/24", reason="first", added_by="alice")
    first = svc.list_rules()[0]
    svc.add_rule("10.0.0.0/24", reason="second", added_by="alice")
    rules = svc.list_rules()
    assert len(rules) == 1 and rules[0]["id"] == first["id"] and rules[0]["reason"] == "second"


def test_ips_come_back_as_plain_text(ip_service):
    svc, tmp = ip_service
    svc.add_rule("1.2.3.4")
    svc.add_rule("10.0.0.0/24")
    assert {r["ip"] for r in svc.list_rules()} == {"1.2.3.4", "10.0.0.0/24"}
    assert all(isinstance(r["created_at"], int) for r in svc.list_rules())
    assert (tmp / "global_blocklist.txt").read_text().split() == ["10.0.0.0/24", "1.2.3.4"]


def test_bad_input_is_a_value_error_or_false_never_a_crash(ip_service):
    svc, _ = ip_service
    with pytest.raises(ValueError):
        svc.add_rule("bad")
    assert svc.delete_rule("not-an-ip") is False
    assert svc.bulk_delete(["nope", "also-bad"]) == 0


def test_search_matches_who_added_it(ip_service):
    svc, _ = ip_service
    svc.add_rule("5.6.7.8", added_by="carol")
    svc.add_rule("5.6.7.9", added_by="dave")
    assert [r["ip"] for r in svc.list_rules(search="caro")] == ["5.6.7.8"]


def test_an_expired_ban_leaves_the_table_and_the_file(ip_service):
    svc, tmp = ip_service
    from db import pool
    svc.add_rule("9.9.9.9", duration_seconds=3600)
    pool.exec_("UPDATE ip_rules SET expires_at = now() - interval '1 second'")
    from services.retention_worker import expire_ip_bans
    assert expire_ip_bans(svc) == 1
    assert svc._pg.list() == []
    assert "9.9.9.9" not in (tmp / "global_blocklist.txt").read_text()


def test_rate_rule_shape_and_update(monkeypatch):
    from db import pool
    import services.rate_limit_service as r
    monkeypatch.setenv("DATA_BACKEND", "postgres")
    pool.close_pool()
    svc = r.RateLimitService()
    assert {x["id"] for x in svc.list_rules()} == {"rule_auth_protect", "rule_global_api", "rule_edge_flood"}
    added = svc.add_rule("t", "/x/*", 5, 60, method="get")
    updated = svc.update_rule(added["id"], {"enabled": 0, "method": "post"})
    assert updated["enabled"] == 0 and isinstance(updated["enabled"], int) and updated["method"] == "POST"
    assert isinstance(updated["created_at"], int) and updated["created_at"] <= int(time.time())
    assert svc.delete_rule(added["id"]) is True and svc.delete_rule(added["id"]) is False
    pool.close_pool()


def test_retention_runs_as_maintenance_and_not_as_the_app():
    import psycopg
    admin = pg_harness.admin_connection()
    role = "t_maint_login"
    admin.execute(f"DROP ROLE IF EXISTS {role}")
    admin.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'x' IN ROLE waf_maintenance")
    try:
        dsn = psycopg.conninfo.make_conninfo(pg_harness.ensure_database(), user=role, password="x")
        with psycopg.connect(dsn, autocommit=True) as conn:
            rows = conn.execute("SELECT table_name FROM waf.run_retention()").fetchall()
        assert [r[0] for r in rows] == ["audit_logs", "threat_patterns", "status_history_days", "alerts"]
        from db import pool
        pool.close_pool()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            pool.q("SELECT * FROM waf.run_retention()")
        pool.close_pool()
    finally:
        admin.execute(f"DROP ROLE IF EXISTS {role}")
