"""Live "top offenders" panel beside the histogram: the busiest IPs, paths and
attack types in the current filter window, so an attack is readable without
opening an incident. Reuses the shared log filter clauses (tenant scope, time
bounds, status/severity), so the panel always matches what the chart shows."""
import types

import pytest

from services.clickhouse_service import ClickHouseService


def _svc(result_by_col=None):
    """Mock that answers each GROUP BY query from result_by_col keyed by the
    grouped column, and records every query it was asked."""
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = True
    ch._queries = []

    class _Client:
        def query(self, q):
            ch._queries.append(q)
            rows = []
            for col, data in (result_by_col or {}).items():
                if f"{col} AS k" in q:
                    rows = data
                    break
            return types.SimpleNamespace(result_rows=rows)

    ch.client = _Client()
    return ch


def test_not_connected_returns_empty_lists():
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = False
    out = ch.top_offenders()
    assert out == {"top_ips": [], "top_paths": [], "top_types": []}


def test_groups_three_dimensions_newest_filter_applied():
    ch = _svc({
        "client_ip": [("1.2.3.4", 40), ("5.6.7.8", 9)],
        "url": [("/wp-login.php", 30), ("/.env", 12)],
        "attack_type": [("SQL Injection", 22)],
    })
    out = ch.top_offenders(n=5, status_filter="BLOCKED", from_ts=1700000000, to_ts=1700003600)
    assert out["top_ips"] == [["1.2.3.4", 40], ["5.6.7.8", 9]]
    assert out["top_paths"] == [["/wp-login.php", 30], ["/.env", 12]]
    assert out["top_types"] == [["SQL Injection", 22]]
    # every dimension query carries the shared filters (blocked + time bounds)
    for q in ch._queries:
        assert "toDateTime(1700000000)" in q
        assert "(status_code = 403 OR status_code = 429)" in q
        assert "GROUP BY k" in q and "ORDER BY" in q and "LIMIT 5" in q


def test_blank_keys_dropped_and_limit_clamped():
    ch = _svc({
        "client_ip": [("1.2.3.4", 3), ("", 99)],  # empty IP must not appear
        "url": [],
        "attack_type": [("", 5)],
    })
    out = ch.top_offenders(n=1000)
    assert out["top_ips"] == [["1.2.3.4", 3]]
    assert out["top_types"] == []
    assert "LIMIT 50" in ch._queries[0]  # n clamped to 50


def test_tenant_scope_clause_forwarded():
    ch = _svc({})
    ch.top_offenders(origin_clause="host IN ('a.com')")
    assert all("host IN ('a.com')" in q for q in ch._queries)
