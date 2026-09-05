"""
Scenario: Phase 2 (docs/IMPLEMENTATION-ROADMAP.md) -- nginx already logs
request_id, http_referer, and body_bytes_sent (see nginx/nginx.conf's
json_combined log_format and log_forward.py's normalize_access(), which already
extracts all three), but access_logs' ClickHouse schema had no column for any of
them, so save_log() silently dropped them on every insert.

Schema now has the three columns (added via ALTER TABLE ADD COLUMN on Main,
2026-09-05, backed up and verified beforehand -- see
docs/IMPLEMENTATION-ROADMAP.md Phase 2). This test locks in that save_log()
actually populates them, using a fake client that records what would have been
sent to ClickHouse rather than a live connection.
"""
from services.clickhouse_service import ClickHouseService


class _RecordingClient:
    def __init__(self):
        self.inserted_rows = None
        self.inserted_columns = None
        self.table_name = None

    def insert(self, table_name, rows, column_names=None):
        self.table_name = table_name
        self.inserted_rows = rows
        self.inserted_columns = column_names


def _make_service_with_fake_client():
    svc = ClickHouseService.__new__(ClickHouseService)
    svc.connected = True
    svc.client = _RecordingClient()
    return svc


def test_save_log_populates_request_id_referer_and_body_bytes_sent():
    svc = _make_service_with_fake_client()
    ok = svc.save_log("access_logs", {
        "request_id": "abc-123",
        "ip": "1.2.3.4",
        "method": "GET",
        "url": "/index.html",
        "status": 200,
        "http_referer": "https://example.com/",
        "body_bytes_sent": 4096,
        "edge_node": "edge-th",
    })
    assert ok is True

    columns = svc.client.inserted_columns
    row = svc.client.inserted_rows[0]
    row_by_col = dict(zip(columns, row))

    assert row_by_col["request_id"] == "abc-123"
    assert row_by_col["http_referer"] == "https://example.com/"
    assert row_by_col["body_bytes_sent"] == 4096


def test_save_log_defaults_new_columns_safely_when_absent():
    svc = _make_service_with_fake_client()
    ok = svc.save_log("access_logs", {
        "ip": "1.2.3.4",
        "method": "GET",
        "url": "/",
        "status": 200,
    })
    assert ok is True

    columns = svc.client.inserted_columns
    row = svc.client.inserted_rows[0]
    row_by_col = dict(zip(columns, row))

    assert row_by_col["request_id"] == ""
    assert row_by_col["http_referer"] == ""
    assert row_by_col["body_bytes_sent"] == 0
