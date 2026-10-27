"""
Scenario: services/blast_radius_service.py fetched its replay corpus with
ClickHouseService.get_traffic_sample_for_simulation(), which did not exist.
The AttributeError was caught and logged, so every blast-radius simulation
ran on synthetic traffic only and never on the platform's real requests.
"""
from unittest.mock import MagicMock

from services.blast_radius_service import BlastRadiusService
from services.clickhouse_service import ClickHouseService


def _service_with_rows(rows):
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = True
    result = MagicMock()
    result.result_rows = rows
    ch.client = MagicMock()
    ch.client.query.return_value = result
    return ch


def test_sample_query_reads_recent_access_logs_as_bound_parameters():
    ch = _service_with_rows([("/login", "GET", 200, "192.0.2.10", "Mozilla/5.0", 0, "", "shop.example.com")])
    rows = ch.get_traffic_sample_for_simulation(time_range_hours=24, limit=500)
    assert rows == [{"url": "/login", "method": "GET", "status": 200, "ip": "192.0.2.10",
                     "user_agent": "Mozilla/5.0", "alert": 0, "attack_type": "", "host": "shop.example.com"}]
    query, kwargs = ch.client.query.call_args[0][0], ch.client.query.call_args[1]
    assert "FROM access_logs" in query
    assert kwargs["parameters"] == {"hours": 24, "limit": 500}


def test_sample_is_empty_without_a_connection():
    ch = ClickHouseService.__new__(ClickHouseService)
    ch.connected = False
    assert ch.get_traffic_sample_for_simulation() == []


def test_simulation_replays_the_real_requests():
    marker = "/only-in-real-traffic-7f3a"
    real = [(marker, "GET", 200, "192.0.2.10", "Mozilla/5.0", 0, "", "shop.example.com")] * 3
    svc = BlastRadiusService(clickhouse_service=_service_with_rows(real))
    result = svc.simulate(variable="REQUEST_URI", operator=f"@contains {marker}", severity="CRITICAL", sample_limit=50)
    assert result["matched_count"] == 3
    assert result["legitimate_matched_count"] == 3


# ---- domain_id picks traffic by host (2026-10-27) ------------------------------
# It used to keep rows whose url or user_agent merely contained the name, after
# the 2000-row limit: url holds no host, so a per-domain run replayed nothing
# real, and a request elsewhere that mentioned the name was counted.

def test_a_domain_scope_is_an_exact_host_clause_inside_the_query():
    ch = _service_with_rows([])
    svc = BlastRadiusService(clickhouse_service=ch)
    svc.simulate(variable="REQUEST_URI", operator="@contains /x", sample_limit=20, domain_id="Shop.Example.com.")
    query = ch.client.query.call_args[0][0]
    assert "AND ((host = 'shop.example.com'))" in query
    assert query.index("host = ") < query.index("LIMIT")  # filtered before the limit


def test_an_origin_id_scopes_to_that_origins_hosts(monkeypatch):
    import services.tenant_service as ts
    oid = "11111111-2222-3333-4444-555555555555"
    monkeypatch.setattr(ts, "origin_traffic_filter", lambda o: "((host = 'a.example.com'))" if o == oid else "1=0")
    ch = _service_with_rows([])
    BlastRadiusService(clickhouse_service=ch).simulate(variable="REQUEST_URI", operator="@contains /x",
                                                       sample_limit=20, domain_id=oid)
    assert "AND (((host = 'a.example.com')))" in ch.client.query.call_args[0][0]


def test_all_means_every_host():
    ch = _service_with_rows([])
    BlastRadiusService(clickhouse_service=ch).simulate(variable="REQUEST_URI", operator="@contains /x",
                                                       sample_limit=5, domain_id="ALL")
    assert "host =" not in ch.client.query.call_args[0][0]
