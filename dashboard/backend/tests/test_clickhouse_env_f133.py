"""F-133: ClickHouse credentials come from the environment, with no default
password (the old default was a well-known value in the public repo)."""
from pathlib import Path

import clickhouse_connect

from services import clickhouse_service
from services.clickhouse_service import ClickHouseService


def test_settings_come_from_env(monkeypatch):
    seen = {}
    monkeypatch.setenv("CLICKHOUSE_HOST", "ch.internal")
    monkeypatch.setenv("CLICKHOUSE_PORT", "18123")
    monkeypatch.setenv("CLICKHOUSE_USER", "reader")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "from-env")
    monkeypatch.setattr(ClickHouseService, "init_db", lambda self: None)
    monkeypatch.setattr(clickhouse_connect, "get_client", lambda **kw: seen.update(kw) or object())

    svc = ClickHouseService()

    assert svc.connected is True
    assert seen == {"host": "ch.internal", "port": 18123, "username": "reader", "password": "from-env"}


def test_no_password_means_not_connected(monkeypatch):
    monkeypatch.delenv("CLICKHOUSE_PASSWORD", raising=False)
    monkeypatch.setattr(ClickHouseService, "init_db", lambda self: None)

    def must_not_connect(**kw):
        raise AssertionError("connected without a password")

    monkeypatch.setattr(clickhouse_connect, "get_client", must_not_connect)

    assert ClickHouseService().connected is False


def test_no_password_literal_in_source():
    assert "mysecurepassword" not in Path(clickhouse_service.__file__).read_text()
