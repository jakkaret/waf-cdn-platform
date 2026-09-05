"""
Scenario: Phase 2 (docs/IMPLEMENTATION-ROADMAP.md) -- log_forward.py's
normalize_access() silently drops two fields nginx already logs, which then fall
through to fabricated/wrong defaults in clickhouse_service.py's save_log().

Confirmed against live data (docs/PROJECT-DISCOVERY.md, Docs/19 in the separate
Claude_workspace docs tree): of 175,084 rows in ClickHouse's access_logs table,
71.9% carry edge_node="sg" even though no Singapore edge node has ever been
deployed (only Thailand exists), and 68.4% carry request_time_ms=0 even though
nginx's own $request_time field is populated in every request. Root cause is that
normalize_access() (the Main-node-reads-its-own-nginx-log ingestion path) never
extracts request_time, and never sets edge_node at all -- unlike
cdn_log_forward.py's normalize_cdn_access() (the Edge-pushes-to-Main path), which
does both correctly. Both paths ultimately call clickhouse_service.py's save_log(),
whose defaults ("sg", 0.0) were written to look plausible rather than to signal
"this wasn't set."

This test locks in two fixes:
1. normalize_access() must extract request_time_ms from nginx's request_time field
   (mirroring cdn_log_forward.py's request_time -> latency_ms computation).
2. normalize_access() must set edge_node explicitly (Main is presently the only
   node that reads its own log this way, so "edge-th" is correct today -- this
   will need revisiting if a second such node is ever added, not silently
   overloaded).
"""
from services.log_forward import normalize_access, normalize_modsec


def test_normalize_access_extracts_request_time_ms():
    nginx_row = {
        "request": "GET /index.html HTTP/1.1",
        "status": "200",
        "request_time": "0.123",
    }
    result = normalize_access(nginx_row)
    assert result["request_time_ms"] == 123.0, (
        f"expected request_time (0.123s) converted to request_time_ms (123.0), "
        f"got {result.get('request_time_ms')!r} -- the field is either missing "
        f"or not converted from seconds to milliseconds"
    )


def test_normalize_access_sets_edge_node():
    nginx_row = {
        "request": "GET /index.html HTTP/1.1",
        "status": "200",
        "request_time": "0.05",
    }
    result = normalize_access(nginx_row)
    assert result.get("edge_node") == "edge-th", (
        f"expected edge_node to be explicitly set to 'edge-th' (Main is the only "
        f"node that ingests via this path), got {result.get('edge_node')!r} -- an "
        f"absent value here falls through to clickhouse_service.py's fabricated "
        f"'sg' default, mislabeling data as coming from a Singapore node that "
        f"has never existed"
    )


def test_normalize_access_request_time_ms_survives_missing_field():
    """A malformed or absent request_time must not crash ingestion -- it should
    degrade to 0, the same fail-safe behavior the rest of this function already
    uses for method/url."""
    nginx_row = {"request": "GET / HTTP/1.1", "status": "200"}
    result = normalize_access(nginx_row)
    assert result["request_time_ms"] == 0.0


def test_normalize_modsec_sets_edge_node():
    """normalize_modsec() feeds try_merge()'s fallback path (flush_old_logs(),
    triggered when no matching access-log entry arrives within MERGE_TIMEOUT) --
    confirmed live on Main 2026-09-05 that this fallback fires under normal
    traffic and, before this fix, produced rows with no edge_node at all
    (falling through to clickhouse_service.py's default). edge_node is a known
    constant for this whole ingestion pipeline (Main is the only node that reads
    its own ModSecurity audit log this way), so normalize_modsec() should carry
    it too, not just normalize_access() -- unlike request_time_ms, which
    ModSecurity's audit log genuinely does not measure and is correctly left
    absent here.
    """
    modsec_row = {"transaction": {"client_ip": "1.2.3.4"}}
    result = normalize_modsec(modsec_row)
    assert result.get("edge_node") == "edge-th"
