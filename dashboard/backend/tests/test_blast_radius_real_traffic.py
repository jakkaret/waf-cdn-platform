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
