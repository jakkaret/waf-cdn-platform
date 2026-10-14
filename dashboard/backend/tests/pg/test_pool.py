"""db/pool.py, db/values.py and db/errors.py against a real PostgreSQL.
Needs TEST_DATABASE_URL (tests/pg_harness.py makes a throwaway database)."""
import uuid

import pytest

from tests import pg_harness

pytestmark = [pytest.mark.pg,
              pytest.mark.skipif(not pg_harness.enabled(), reason="TEST_DATABASE_URL not set")]


@pytest.fixture(autouse=True)
def _db():
    pg_harness.ensure_database()
    from db import pool
    pool.close_pool()  # pick up DATABASE_URL of this test database
    yield
    pool.close_pool()


def test_ping():
    from db import pool
    assert pool.ping() is True


def test_creating_the_pool_does_no_io(monkeypatch):
    from db import pool
    pool.close_pool()
    monkeypatch.setenv("DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
    p = pool.get_pool()          # built, not opened
    assert p.closed
    assert pool.ping(timeout=0.5) is False
    pool.close_pool()


def test_nested_transaction_rolls_back_only_the_savepoint():
    from db import pool
    from db.errors import ConstraintError
    email = f"nested-{uuid.uuid4().hex[:8]}@example.com"
    with pool.transaction():
        pool.exec_("INSERT INTO users (email, username, password_hash) VALUES (%s, 'n', '$argon2id$x')",
                   (email,))
        with pytest.raises(ConstraintError):
            with pool.transaction():
                pool.exec_("INSERT INTO users (email, username) VALUES ('bad@example.com', 'b')")
    assert pg_harness.count("users", "email = %s", (email,)) == 1
    assert pg_harness.count("users", "email = 'bad@example.com'") == 0


def test_outer_failure_rolls_back_everything():
    from db import pool
    email = f"outer-{uuid.uuid4().hex[:8]}@example.com"
    with pytest.raises(RuntimeError):
        with pool.transaction():
            pool.exec_("INSERT INTO users (email, username, password_hash) VALUES (%s, 'o', '$argon2id$x')",
                       (email,))
            raise RuntimeError("boom")
    assert pg_harness.count("users", "email = %s", (email,)) == 0


def test_uuid_columns_come_back_as_str():
    from db import pool
    row = pool.q1("INSERT INTO users (email, username, password_hash) "
                  "VALUES (%s, 'u', '$argon2id$x') RETURNING user_id",
                  (f"uuid-{uuid.uuid4().hex[:8]}@example.com",))
    assert isinstance(row["user_id"], str)
    assert uuid.UUID(row["user_id"])


def test_constraint_errors_become_value_errors_without_internal_names():
    from db import pool
    from db.errors import ConstraintError, UniqueConflict
    with pytest.raises(ConstraintError) as check:
        pool.exec_("INSERT INTO users (email, username) VALUES ('nopw@example.com', 'x')")
    assert isinstance(check.value, ValueError)
    assert "users_local_has_password" not in str(check.value)
    assert check.value.constraint == "users_local_has_password"
    email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    pool.exec_("INSERT INTO users (email, username, password_hash) VALUES (%s, 'd', '$argon2id$x')", (email,))
    with pytest.raises(UniqueConflict):
        pool.exec_("INSERT INTO users (email, username, password_hash) VALUES (%s, 'd2', '$argon2id$x')",
                   (email.upper(),))


def test_app_role_cannot_rewrite_audit_history():
    from db import pool
    from db.errors import ConstraintError
    import psycopg
    pool.exec_("INSERT INTO audit_logs (event_id, scope_id, action, summary) "
               "VALUES ('00000000000000000009#cafebabe', 'global', 'test', 't')")
    for sql in ("UPDATE audit_logs SET summary = 'x'", "DELETE FROM audit_logs"):
        with pytest.raises((psycopg.errors.InsufficientPrivilege, ConstraintError)):
            pool.exec_(sql)


def test_as_uuid():
    from db.values import as_uuid
    u = uuid.uuid4()
    assert as_uuid("not-a-uuid") is None
    assert as_uuid(None) is None
    assert as_uuid("o1") is None
    assert as_uuid(str(u).upper()) == str(u)
    assert as_uuid(u) == str(u)


def test_time_formats_keep_each_tables_shape():
    from datetime import datetime, timezone
    from db import values as types
    t = datetime(2026, 10, 15, 3, 4, 5, 123456, tzinfo=timezone.utc)
    assert types.iso_z_us(t) == "2026-10-15T03:04:05.123456Z"
    assert types.iso_z_s(t) == "2026-10-15T03:04:05Z"
    assert types.iso_offset(t) == "2026-10-15T03:04:05.123456+00:00"
    assert types.naive_utc(t) == "2026-10-15 03:04:05"
    assert types.date_text(t.date()) == "2026-10-15"
    assert types.epoch_str(t) == str(int(t.timestamp()))
    assert types.parse_ts("2026-10-15T03:04:05.123456Z") == t
    for value in (types.iso_z_us(t), types.iso_offset(t)):
        assert datetime.fromisoformat(value.replace("Z", "+00:00")) == t
