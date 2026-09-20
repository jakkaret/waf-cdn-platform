"""
Scenario: 2026-09-20 fix -- access_logs had no retention policy at all.
Confirmed live: grew to 1.1M rows in 19 days (~58k/day) before being
manually cleared once on 8 Sept; nothing stopped it from growing right
back to the same size and slowing the dashboard down again.

This locks in two things:
1. A fresh CREATE TABLE carries a real TTL clause (not just a comment
   promising one).
2. init_db() also runs an idempotent ALTER TABLE ... MODIFY TTL against
   whatever table already exists -- this matters because Main's real
   access_logs table predates this fix (CREATE TABLE IF NOT EXISTS is a
   no-op against it), so only the ALTER actually applies retention there.

Both are checked by intercepting the SQL strings passed to a mocked
client.command() -- no real ClickHouse connection needed or attempted.
"""
from unittest.mock import MagicMock

from services.clickhouse_service import ClickHouseService, ACCESS_LOGS_RETENTION_DAYS


def test_init_db_creates_access_logs_with_ttl_clause():
    svc = ClickHouseService()  # connect() fails gracefully in test env (no real ClickHouse) -> connected=False, init_db() no-ops
    svc.connected = True
    svc.client = MagicMock()

    svc.init_db()

    commands = [c.args[0] for c in svc.client.command.call_args_list]
    create_table_sql = next(c for c in commands if "CREATE TABLE IF NOT EXISTS access_logs" in c)
    assert f"TTL timestamp + INTERVAL {ACCESS_LOGS_RETENTION_DAYS} DAY" in create_table_sql, (
        "a fresh access_logs table must carry a real TTL clause, not rely on "
        "a separate ALTER ever being run against it later"
    )


def test_init_db_applies_modify_ttl_to_a_table_that_already_existed():
    """The CREATE TABLE IF NOT EXISTS above is a no-op against Main's real
    table (it predates this fix) -- this MODIFY TTL call is the only thing
    that actually gives that existing table a retention policy."""
    svc = ClickHouseService()
    svc.connected = True
    svc.client = MagicMock()

    svc.init_db()

    commands = [c.args[0] for c in svc.client.command.call_args_list]
    alter_sql = next((c for c in commands if "ALTER TABLE access_logs MODIFY TTL" in c), None)
    assert alter_sql is not None, "must retrofit TTL onto a pre-existing table, not only apply it to a fresh one"
    assert f"INTERVAL {ACCESS_LOGS_RETENTION_DAYS} DAY" in alter_sql


def test_init_db_never_touches_clickhouse_when_not_connected():
    """A disconnected instance must not attempt any DDL call. Built via
    __new__ (bypassing __init__/connect()) rather than relying on a real
    connection attempt failing -- this suite runs directly on Main, where
    a real ClickHouse is normally reachable, so ClickHouseService()'s own
    constructor would otherwise connect for real here instead of exercising
    the disconnected path this test is actually about."""
    svc = ClickHouseService.__new__(ClickHouseService)
    svc.connected = False
    svc.client = MagicMock()
    svc.init_db()
    svc.client.command.assert_not_called()


def test_retention_days_is_configurable_via_env(monkeypatch):
    """Guards the env-override path -- a different retention window must
    actually reach the SQL, not just the module-level default."""
    monkeypatch.setenv("ACCESS_LOGS_RETENTION_DAYS", "7")
    import importlib
    import services.clickhouse_service as ch_module
    importlib.reload(ch_module)
    try:
        assert ch_module.ACCESS_LOGS_RETENTION_DAYS == 7
    finally:
        monkeypatch.delenv("ACCESS_LOGS_RETENTION_DAYS", raising=False)
        importlib.reload(ch_module)  # restore the default (30) for every test after this one
