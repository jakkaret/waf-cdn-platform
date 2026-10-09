"""Log viewing at scale: keyset (cursor) pagination instead of deep OFFSET, a
time-bucket histogram, and dropping internal /healthz noise by default."""
import types

import pytest

from services.clickhouse_service import ClickHouseService


def _svc(rows=None):
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = True
    captured = {}

    class _Client:
        def query(self, q):
            captured["q"] = q
            return types.SimpleNamespace(result_rows=rows or [])

    ch.client = _Client()
    ch._captured = captured
    return ch


# ---- filter helper (pure) ----
def test_health_noise_excluded_by_default():
    ch = _svc()
    w = ch._log_filter_clauses()
    assert any("url != '/healthz'" in c for c in w)
    w2 = ch._log_filter_clauses(exclude_health=False)
    assert not any("healthz" in c for c in w2)


def test_time_bounds_are_integer_epoch():
    ch = _svc()
    w = ch._log_filter_clauses(from_ts=1700000000, to_ts=1700003600)
    assert any("toDateTime(1700000000)" in c for c in w) and any("toDateTime(1700003600)" in c for c in w)


def test_status_and_severity_mapping():
    ch = _svc()
    w = ch._log_filter_clauses(status_filter="BLOCKED", severity_filter="HIGH")
    assert any("403" in c and "429" in c for c in w)
    assert any("status_code >= 500" in c for c in w)


# ---- keyset ----
def test_keyset_orders_and_fetches_one_extra():
    rows = [("id%d" % i, "2026-10-09 00:00:%02d" % i, 1000 + i, "1.2.3.4", "GET", "/", 200,
             "ua", "TH", "edge-th", "", "", "NONE") for i in range(51)]
    ch = _svc(rows)
    out = ch.query_logs_keyset(limit=50)
    q = ch._captured["q"]
    assert "ORDER BY timestamp DESC, id DESC" in q
    assert "LIMIT 51" in q  # limit + 1
    assert "url != '/healthz'" in q
    assert out["has_more"] is True
    assert len(out["logs"]) == 50
    assert out["next_cursor"]["id"] == "id49"  # last RETURNED row (row 50 was the probe)


def test_keyset_no_more_when_short_page():
    rows = [("a", "2026-10-09 00:00:00", 1000, "1.2.3.4", "GET", "/", 200,
             "ua", "TH", "edge-th", "", "", "NONE")]
    ch = _svc(rows)
    out = ch.query_logs_keyset(limit=50)
    assert out["has_more"] is False and out["next_cursor"] is None


def test_keyset_cursor_clause_added_and_uuid_validated():
    ch = _svc([])
    ch.query_logs_keyset(limit=10, cursor_ts=1700000000,
                         cursor_id="11111111-2222-3333-4444-555555555555")
    assert "toUUID('11111111-2222-3333-4444-555555555555')" in ch._captured["q"]
    # a non-UUID cursor id must be ignored (no injection into the query)
    ch2 = _svc([])
    ch2.query_logs_keyset(limit=10, cursor_ts=1700000000, cursor_id="'; DROP TABLE x;--")
    assert "DROP TABLE" not in ch2._captured["q"]
    assert "toUUID(" not in ch2._captured["q"]


# ---- histogram ----
def test_histogram_buckets_and_blocked_count():
    rows = [(1700000000, 10, 3), (1700003600, 5, 1)]
    ch = _svc(rows)
    out = ch.logs_histogram(bucket_seconds=3600)
    q = ch._captured["q"]
    assert "toStartOfInterval(timestamp, INTERVAL 3600 SECOND)" in q
    assert "countIf(status_code = 403 OR status_code = 429)" in q
    assert out == [{"bucket": 1700000000, "total": 10, "blocked": 3},
                   {"bucket": 1700003600, "total": 5, "blocked": 1}]


def test_not_connected_returns_empty():
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = False
    assert ch.query_logs_keyset()["logs"] == []
    assert ch.logs_histogram() == []
