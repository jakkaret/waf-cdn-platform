"""Schema + migration runner tests against a real, throwaway PostgreSQL.

Skipped unless TEST_DATABASE_URL points at a server where that user may
CREATE DATABASE and CREATE ROLE (a local dev cluster, never production).
Each run creates its own database waf_test_<hex> and drops it afterwards.
"""
import os
import uuid
from contextlib import contextmanager

import pytest

psycopg = pytest.importorskip("psycopg")

from db import migrate as migrate_mod  # noqa: E402

ADMIN_DSN = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not ADMIN_DSN, reason="TEST_DATABASE_URL not set")


def _dsn_for(dbname: str) -> str:
    return psycopg.conninfo.make_conninfo(ADMIN_DSN, dbname=dbname)


@pytest.fixture(scope="module")
def db():
    name = "waf_test_" + uuid.uuid4().hex[:10]
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        applied = migrate_mod.migrate(_dsn_for(name))
        with psycopg.connect(_dsn_for(name), autocommit=True) as conn:
            conn.execute("SET search_path = waf, public")
            yield {"name": name, "conn": conn, "applied": applied}
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@contextmanager
def _as_role(conn, group):
    """Run as a throwaway LOGIN-less member of a group role, then drop it."""
    role = f"t_{group}_{uuid.uuid4().hex[:8]}"
    conn.execute(f"CREATE ROLE {role} IN ROLE {group}")
    conn.execute(f"SET ROLE {role}")
    try:
        yield
    finally:
        conn.execute("RESET ROLE")
        conn.execute(f"DROP ROLE {role}")


def _err(conn, sql, params=None) -> str:
    with pytest.raises(psycopg.Error) as ei:
        conn.execute(sql, params)
    return str(ei.value).splitlines()[0]


def test_migrate_applies_init_once_then_is_up_to_date(db):
    expected = [p.stem for p in migrate_mod.migration_files()]
    assert expected[:3] == ["0001_init", "0002_seed_rate_limit_rules", "0003_origin_owner_delete_archives"]
    assert db["applied"] == expected
    assert migrate_mod.migrate(_dsn_for(db["name"])) == []


def test_all_tables_and_view_exist(db):
    c = db["conn"]
    tables = {r[0] for r in c.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='waf' AND table_type='BASE TABLE'")}
    # 0006 origin_invites, 0007 tunnel_proxy_owners, 0008 user_sessions, 0009 support (4 tables),
    # 0010 drops bola_policies, 0011 email_codes + email_code_sends, 0012 alert_incidents,
    # 0013 site_outages + audit_notified
    assert len(tables - {"schema_migrations"}) == 30
    assert {"email_codes", "email_code_sends"} <= tables
    assert {"alert_incidents", "site_outages", "audit_notified"} <= tables
    assert "bola_policies" not in tables
    assert "origin_invites" in tables
    assert "tunnel_proxy_owners" in tables
    assert "user_sessions" in tables
    assert {"support_tickets", "support_ticket_messages", "support_grants", "support_access_log"} <= tables
    assert "schema_migrations" in tables
    views = {r[0] for r in c.execute(
        "SELECT table_name FROM information_schema.views WHERE table_schema='waf'")}
    assert views == {"origin_hostnames"}


def test_constraints_and_relations(db):
    c = db["conn"]
    uid = c.execute(
        "INSERT INTO users(email,username,role,password_hash) "
        "VALUES('A@x.com','a','admin','$argon2id$v=19$x') RETURNING user_id").fetchone()[0]
    assert "users_local_has_password" in _err(
        c, "INSERT INTO users(email,username) VALUES('b@x.com','b')")
    assert "argon2" in _err(
        c, "INSERT INTO users(email,username,password_hash) VALUES('c@x.com','c','plain')")
    assert "users_email_uk" in _err(
        c, "INSERT INTO users(email,username,password_hash) VALUES('a@X.com','a2','$argon2id$z')")

    gid = c.execute(
        "INSERT INTO users(email,username,auth_provider) VALUES('g@x.com','g','google') "
        "RETURNING user_id").fetchone()[0]
    c.execute("INSERT INTO user_identities(provider,provider_user_id,user_id) "
              "VALUES('google','sub-1',%s)", (gid,))

    o1 = c.execute("INSERT INTO origins(admin_user_id,label,ip,port) "
                   "VALUES(%s,'o1','10.0.0.1',80) RETURNING id", (uid,)).fetchone()[0]
    o2 = c.execute("INSERT INTO origins(admin_user_id,label,ip,port) "
                   "VALUES(%s,'o2','10.0.0.2',80) RETURNING id", (uid,)).fetchone()[0]
    c.execute("INSERT INTO origin_members(origin_id,user_id,role) "
              "VALUES(%s,%s,'viewer'),(%s,%s,'editor')", (o1, gid, o1, gid))
    c.execute("INSERT INTO domains(origin_id,domain_name,verification_token) "
              "VALUES(%s,'shop.example.com','waf-token-1')", (o1,))
    c.execute("INSERT INTO origin_tunnel_domains(origin_id,domain_name) "
              "VALUES(%s,'api.example.com')", (o1,))
    assert "origin_tunnel_domains_domain_uk" in _err(
        c, "INSERT INTO origin_tunnel_domains(origin_id,domain_name) "
           "VALUES(%s,'api.example.com')", (o2,))
    c.execute("INSERT INTO origin_agent_credentials(origin_id,token_hash,issued_by) "
              "VALUES(%s,%s,%s)", (o1, "a" * 64, uid))
    n = c.execute("SELECT count(*) FROM origin_hostnames WHERE origin_id=%s",
                  (o1,)).fetchone()[0]
    assert n == 2

    c.execute("INSERT INTO alerts(alert_id,ip,url,status) "
              "VALUES('ALT-1','1.2.3.4','/x','403')")
    for _ in range(3):
        c.execute(
            "INSERT INTO status_history_days(component_id,date_bucket,name,sample_count,"
            "healthy_count) VALUES('th',current_date,'Thailand',1,1) "
            "ON CONFLICT(component_id,date_bucket) DO UPDATE SET "
            "sample_count=status_history_days.sample_count+1, "
            "healthy_count=status_history_days.healthy_count+excluded.healthy_count")
    assert c.execute("SELECT sample_count,healthy_count FROM status_history_days"
                     ).fetchone() == (3, 3)
    c.execute("INSERT INTO pending_rules(dedup_key) VALUES('k1')")
    assert "pending_rules_pending_dedup_uk" in _err(
        c, "INSERT INTO pending_rules(dedup_key) VALUES('k1')")


def test_default_rate_limit_rules_are_seeded(db):
    rows = db["conn"].execute(
        "SELECT id, method, limit_count, window_seconds, burst, action, enabled "
        "FROM rate_limit_rules ORDER BY id").fetchall()
    assert rows == [
        ("rule_auth_protect", "POST", 10, 60, 2, "429", True),
        ("rule_edge_flood", "ALL", 50, 1, 10, "429", True),
        ("rule_global_api", "ALL", 120, 60, 20, "429", True),
    ]


def test_deleting_an_origin_owner_needs_the_origins_archived_first(db):
    c = db["conn"]
    uid = c.execute("INSERT INTO users(email,username,password_hash) "
                    "VALUES('owner-del@x.com','od','$argon2id$x') RETURNING user_id").fetchone()[0]
    oid = c.execute("INSERT INTO origins(admin_user_id,label,ip,port,status) "
                    "VALUES(%s,'live','10.0.0.9',80,'active') RETURNING id", (uid,)).fetchone()[0]
    # A live origin may not lose its owner.
    assert "origins_owner_unless_archived" in _err(c, "DELETE FROM users WHERE user_id=%s", (uid,))
    c.execute("UPDATE origins SET status='archived', archived_at=now() WHERE id=%s", (oid,))
    c.execute("DELETE FROM users WHERE user_id=%s", (uid,))
    assert c.execute("SELECT admin_user_id, status FROM origins WHERE id=%s", (oid,)).fetchone() == (None, "archived")
    assert "origins_owner_unless_archived" in _err(
        c, "UPDATE origins SET status='active' WHERE id=%s", (oid,))


def test_audit_logs_are_append_only(db):
    c = db["conn"]
    c.execute("INSERT INTO audit_logs(event_id,scope_id,action,summary) "
              "VALUES('00000001760000000000#deadbeef','global','origin.update','x')")
    assert "append-only" in _err(c, "UPDATE audit_logs SET summary='y'")
    assert "younger than 180 days" in _err(c, "DELETE FROM audit_logs")
    assert "append-only" in _err(c, "TRUNCATE audit_logs")


def test_app_role_privileges(db):
    c = db["conn"]
    with _as_role(c, "waf_app"):
        c.execute("INSERT INTO audit_logs(event_id,scope_id,action,summary) "
                  "VALUES('00000001760000000001#deadbeef','global','settings.update','x')")
        assert "permission denied" in _err(c, "DELETE FROM audit_logs")
        assert "permission denied" in _err(c, "UPDATE audit_logs SET summary='y'")
        assert "permission denied" in _err(c, "TRUNCATE audit_logs")
        assert "must be owner" in _err(c, "ALTER TABLE audit_logs DISABLE TRIGGER ALL")
        c.execute("SELECT count(*) FROM origin_hostnames")


def test_maintenance_role_runs_retention(db):
    c = db["conn"]
    with _as_role(c, "waf_maintenance"):
        rows = c.execute("SELECT table_name FROM run_retention()").fetchall()
    assert [r[0] for r in rows] == ["audit_logs", "threat_patterns", "status_history_days", "alerts"]


def test_dry_run_reports_pending_without_applying(tmp_path):
    name = "waf_test_" + uuid.uuid4().hex[:10]
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        assert migrate_mod.migrate(_dsn_for(name), dry_run=True) == [
            p.stem for p in migrate_mod.migration_files()]
        with psycopg.connect(_dsn_for(name)) as conn:
            assert conn.execute("SELECT to_regclass('waf.users')").fetchone()[0] is None
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
