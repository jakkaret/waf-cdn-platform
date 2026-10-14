"""Throwaway PostgreSQL database for the test suite.

TEST_DATABASE_URL must point at a server where that user may CREATE DATABASE
and CREATE ROLE (a local/CI cluster, never production). ensure_database():
  - creates database waf_test_<hex>, applies db/migrations as that admin;
  - creates a LOGIN role inside waf_app (the production app's group role)
    and points DATABASE_URL at it, so a missing GRANT fails in tests too;
  - drops both at interpreter exit.
reset() empties every table between tests (TRUNCATE as superuser with
session_replication_role=replica, which also skips the audit_logs
append-only trigger) and re-seeds the default rate-limit rules.

Why not one rolled-back outer transaction per test: router tests run the
app on TestClient's portal thread and through asyncio.to_thread, where the
test's connection (a contextvar) does not follow, so app writes would
commit on other connections and leak into the next test.
"""
from __future__ import annotations

import atexit
import os
import secrets
from pathlib import Path
from typing import Optional

ADMIN_DSN = os.environ.get("TEST_DATABASE_URL", "").strip()
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_state: dict = {}


def enabled() -> bool:
    return bool(ADMIN_DSN)


def _dsn(dbname: str, **overrides) -> str:
    import psycopg
    return psycopg.conninfo.make_conninfo(ADMIN_DSN, dbname=dbname, **overrides)


def ensure_database() -> str:
    """Create (once per process) the test database; return its admin DSN."""
    if "admin_dsn" in _state:
        return _state["admin_dsn"]
    import psycopg
    from db import migrate

    suffix = secrets.token_hex(5)
    dbname = f"waf_test_{suffix}"
    role = f"waf_test_app_{suffix}"
    password = secrets.token_hex(16)
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{dbname}"')
    admin_dsn = _dsn(dbname)
    migrate.migrate(admin_dsn)
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}' IN ROLE waf_app")
        conn.execute(f'GRANT CONNECT ON DATABASE "{dbname}" TO {role}')
        tables = [r[0] for r in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='waf' "
            "AND tablename <> 'schema_migrations' ORDER BY 1")]
    os.environ["DATABASE_URL"] = _dsn(dbname, user=role, password=password)
    _state.update(admin_dsn=admin_dsn, dbname=dbname, role=role, tables=tables,
                  seed=(_BACKEND_DIR / "db/migrations/0002_seed_rate_limit_rules.sql").read_text())
    atexit.register(_drop)
    return admin_dsn


def admin_connection():
    import psycopg
    if "admin_conn" not in _state or _state["admin_conn"].closed:
        _state["admin_conn"] = psycopg.connect(ensure_database(), autocommit=True)
    return _state["admin_conn"]


def reset() -> None:
    conn = admin_connection()
    tables = ", ".join(f"waf.{t}" for t in _state["tables"])
    with conn.transaction():
        conn.execute("SET LOCAL session_replication_role = replica")
        conn.execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
        conn.execute(_state["seed"])


def count(table: str, where: str = "true", params: Optional[tuple] = None) -> int:
    return admin_connection().execute(
        f"SELECT count(*) FROM waf.{table} WHERE {where}", params).fetchone()[0]


def _drop() -> None:
    import psycopg
    try:
        from db import pool
        pool.close_pool()
    except Exception:
        pass
    conn = _state.pop("admin_conn", None)
    if conn is not None and not conn.closed:
        conn.close()
    try:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{_state["dbname"]}" WITH (FORCE)')
            admin.execute(f'DROP ROLE IF EXISTS {_state["role"]}')
    except Exception as exc:  # never fail the run on cleanup
        print(f"pg_harness cleanup failed: {exc}")
