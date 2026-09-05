"""
Scenario: Phase 2 (docs/IMPLEMENTATION-ROADMAP.md) -- clickhouse_service.py's
save_log() defaulted a missing edge_node to the literal string "sg", which reads
as a plausible real value (a Singapore edge node) but is fabricated: no Singapore
edge node has ever been deployed on this platform (only Thailand exists; see
docs/ARCHITECTURE.md). Confirmed against live data: 71.9% of all 175,084 rows in
ClickHouse's access_logs table carry this fabricated "sg" tag, because
log_forward.py's ingestion path never set edge_node at all before Phase 2 (see
test_log_normalize_fields.py for that half of the fix).

A default should never fabricate a value that looks like real, meaningful data.
Locks in resolve_edge_node(): absent/blank input becomes "unknown" (fails loud,
visible in any breakdown-by-edge-node query) rather than a wrong-but-plausible
node name.
"""
from services.clickhouse_service import resolve_edge_node


def test_missing_edge_node_resolves_to_unknown_not_a_fabricated_region():
    assert resolve_edge_node(None) == "unknown"
    assert resolve_edge_node("") == "unknown"
    assert resolve_edge_node("   ") == "unknown"


def test_real_edge_node_value_passes_through_unchanged():
    assert resolve_edge_node("edge-th") == "edge-th"
    assert resolve_edge_node("edge-sg") == "edge-sg"  # not blocking a future real deploy


def test_resolve_edge_node_strips_incidental_whitespace():
    assert resolve_edge_node("  edge-th  ") == "edge-th"
