"""Apply SQL migrations in dashboard/backend/db/migrations/ to PostgreSQL.

Usage (as the schema owner, never the app role):
    DATABASE_URL_OWNER=postgresql://waf_owner:...@127.0.0.1:5432/waf \
        python db/migrate.py            # apply pending files
    python db/migrate.py --status       # list applied / pending, change nothing

Rules:
- Files run in name order (0001_init.sql, 0002_....sql, ...).
- Each file runs in ONE transaction together with its row in
  waf.schema_migrations, so a failing file leaves nothing half-applied.
- Already-applied versions are skipped; an applied file is never re-run, so
  never edit a file after it reached production: add a new one instead.

The owner DSN is read from DATABASE_URL_OWNER, or from the root-only file named
by WAF_PG_OWNER_ENV (default /root/.waf-secrets/pg_owner.env). It is never
read from the service's .env, so the running app cannot run DDL.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
DEFAULT_OWNER_ENV = "/root/.waf-secrets/pg_owner.env"


def _owner_dsn() -> str:
    dsn = os.environ.get("DATABASE_URL_OWNER", "").strip()
    if dsn:
        return dsn
    env_file = Path(os.environ.get("WAF_PG_OWNER_ENV", DEFAULT_OWNER_ENV))
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "DATABASE_URL_OWNER" and value.strip():
                return value.strip().strip("'\"")
    sys.exit("DATABASE_URL_OWNER is not set (env or %s)" % env_file)


def migration_files(directory: Path = MIGRATIONS_DIR) -> list[Path]:
    # Hidden files (editor swap files, macOS "._" metadata) are never migrations.
    return sorted(p for p in directory.glob("*.sql") if p.is_file() and not p.name.startswith("."))


def applied_versions(conn: psycopg.Connection) -> set[str]:
    exists = conn.execute("SELECT to_regclass('waf.schema_migrations')").fetchone()[0]
    if exists is None:
        return set()
    return {r[0] for r in conn.execute("SELECT version FROM waf.schema_migrations")}


def migrate(dsn: str, directory: Path = MIGRATIONS_DIR, dry_run: bool = False) -> list[str]:
    """Apply pending migrations; return the versions applied (or pending if dry_run)."""
    done: list[str] = []
    with psycopg.connect(dsn, autocommit=True) as conn:
        applied = applied_versions(conn)
        for path in migration_files(directory):
            version = path.stem
            if version in applied:
                continue
            done.append(version)
            if dry_run:
                continue
            with conn.transaction():
                conn.execute(path.read_text())
                conn.execute(
                    "INSERT INTO waf.schema_migrations (version) VALUES (%s)", (version,)
                )
    return done


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--status", action="store_true", help="show pending, change nothing")
    args = parser.parse_args(argv)
    dsn = _owner_dsn()
    if args.status:
        with psycopg.connect(dsn) as conn:
            applied = applied_versions(conn)
        for path in migration_files():
            print(("applied " if path.stem in applied else "PENDING ") + path.stem)
        return 0
    applied_now = migrate(dsn)
    print("applied: " + (", ".join(applied_now) if applied_now else "nothing (up to date)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
