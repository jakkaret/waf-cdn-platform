"""
Scenario: 2026-09-20 fix -- api/cdn.py's /nodes, /stats and /latency
endpoints returned several values that were never measured at all:
`/latency` was a fully hardcoded array including "Singapore (ASEAN)" and
"Tokyo, JP" rows -- regions with no real edge behind them (only TH and
Azure/"ASIA" are real, see REGIONS_META) -- with edge_ms/origin_ms/
savings_pct numbers that never changed no matter what was actually
happening. `/stats` always answered avg_ttfb_ms=26 and a regional_breakdown
with TH/MAIN entries pinned to avg_latency_ms 14/4 and MAIN.requests
hardcoded to 0 even when MAIN had real traffic. `/nodes` claimed
"ssl_status": "active" for every node without ever checking anything.

These tests assert the fabricated literals are gone and the replacements
are derived from real (mocked) inputs -- not that the new numbers are
"correct" in any absolute sense, since correctness here is defined by
"reflects what was actually measured", which is exactly what a mock lets
you control and assert on.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import origins as origins_module
from api import cdn as cdn_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(cdn_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _fake_health_response(ok: bool = True):
    resp = MagicMock()
    resp.status_code = 200 if ok else 500
    return resp


def _patched_httpx_client(online_ips=None):
    """Every _check_node() health GET succeeds; MAIN doesn't need mocking
    since its own code forces online=True on failure anyway."""
    online_ips = online_ips or set()

    client_cm = MagicMock()
    client_instance = MagicMock()

    async def _get(url, *a, **kw):
        return _fake_health_response(ok=True)

    client_instance.get = AsyncMock(side_effect=_get)
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=False)
    return client_cm


def _admin_headers(register_user, auth_header):
    admin = register_user(email="cdn-admin@example.com", username="cdn_admin")
    return auth_header(admin["access_token"])


# --------------------------------------------------------------- /nodes

def test_ssl_status_is_never_the_old_hardcoded_active_for_every_node(
    client: TestClient, register_user, auth_header, monkeypatch
):
    headers = _admin_headers(register_user, auth_header)
    monkeypatch.setattr(cdn_module, "_CDN_NODES_CACHE", (0.0, []))

    async def _open_connection(ip, port):
        if ip == cdn_module.REGIONS_META["TH"]["ip"]:
            return MagicMock(), MagicMock(close=lambda: None)
        raise ConnectionRefusedError("simulated: ASIA edge port 443 closed")

    with patch("api.cdn.httpx.AsyncClient", return_value=_patched_httpx_client()), \
         patch("api.cdn.asyncio.open_connection", side_effect=_open_connection):
        resp = client.get("/api/cdn/nodes", headers=headers)

    assert resp.status_code == 200
    by_region = {n["region"]: n for n in resp.json()}

    # MAIN never had a TLS hop to probe (health_url is a loopback http://
    # call) -- claiming "active" there was never a check at all.
    assert by_region["MAIN"]["ssl_status"] == "not_applicable"
    # TH's simulated probe succeeded.
    assert by_region["TH"]["ssl_status"] == "port_open"
    # ASIA's simulated probe failed -- must NOT still say "active".
    assert by_region["ASIA"]["ssl_status"] == "unreachable"
    assert by_region["ASIA"]["ssl_status"] != "active"


# --------------------------------------------------------------- /stats

def test_zero_origin_account_gets_honest_empty_breakdown_not_fake_th_main(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(cdn_module.ch, "connected", True)
    query_spy = MagicMock(return_value=[])
    monkeypatch.setattr(cdn_module.ch, "query_stats", query_spy)

    register_user(email="cdn-bootstrap@example.com", username="cdn_bootstrap")
    viewer = register_user(email="cdn-zero-origin@example.com", username="cdn_zero_origin", role="viewer")

    resp = client.get("/api/cdn/stats", headers=auth_header(viewer["access_token"]))

    assert resp.status_code == 200
    body = resp.json()
    assert query_spy.call_count == 0, "a zero-origin account must never query ClickHouse at all"
    assert body["regional_breakdown"] == {}, "no invented TH/MAIN rows when there is no real data"
    assert body["avg_ttfb_ms"] == 0
    assert body["total_requests"] == 0


def test_stats_builds_regional_breakdown_from_real_edge_node_rows_not_hardcoded_th_main(
    client: TestClient, register_user, auth_header, monkeypatch
):
    headers = _admin_headers(register_user, auth_header)
    monkeypatch.setattr(cdn_module.ch, "connected", True)

    # First call: grouped-by-edge_node query. Second call: overall avg_ttfb.
    # (edge_node, total_reqs, cache_hits, avg_lat_ms)
    grouped_rows = [
        ("edge-th", 100, 80, 45.0),
        ("some-future-edge", 10, 2, None),  # avgIf() with no matching rows -> NaN in real ClickHouse
    ]
    call_log = []

    def _query_stats(query, *a, **kw):
        call_log.append(query)
        if "GROUP BY edge_node" in query:
            return grouped_rows
        return [[52.3]]  # avg_ttfb query

    monkeypatch.setattr(cdn_module.ch, "query_stats", _query_stats)

    resp = client.get("/api/cdn/stats", headers=headers)
    assert resp.status_code == 200
    body = resp.json()

    assert body["total_requests"] == 110
    assert body["cached_requests"] == 82
    assert body["avg_ttfb_ms"] == 52, "must come from the real avgIf() query, not the old hardcoded 26"

    breakdown = body["regional_breakdown"]
    # "edge-th" maps to the real region code via REGIONS_META's own db_keys
    # -- not a second hand-maintained mapping that can drift.
    assert breakdown["TH"]["requests"] == 100
    assert breakdown["TH"]["avg_latency_ms"] == 45, "must reflect the mocked real avg_lat, not the old hardcoded 14"
    # An edge_node value with no matching REGIONS_META db_key is shown as
    # itself, not silently dropped or forced into a fake existing bucket.
    assert "some-future-edge" in breakdown
    assert breakdown["some-future-edge"]["requests"] == 10
    assert breakdown["some-future-edge"]["avg_latency_ms"] == 0, "NaN from avgIf() with no valid samples must become 0, not crash or fabricate"

    # The old hardcoded shape had exactly {"TH": ..., "MAIN": {"requests": 0, ...}}
    # every single time -- assert that specific fabrication is gone.
    assert "MAIN" not in breakdown or breakdown.get("MAIN", {}).get("requests") != 0 or "edge-main" in [r[0] for r in grouped_rows]


# ------------------------------------------------------------- /latency

def test_latency_never_contains_the_old_fabricated_regions(
    client: TestClient, register_user, auth_header, monkeypatch
):
    headers = _admin_headers(register_user, auth_header)

    with patch("api.cdn.httpx.AsyncClient", return_value=_patched_httpx_client()):
        resp = client.get("/api/cdn/latency", headers=headers)

    assert resp.status_code == 200
    body = resp.json()
    raw_text = str(body)

    for fake_region in ("Singapore", "Tokyo", "Frankfurt, DE", "Chiang Mai"):
        assert fake_region not in raw_text, f"fabricated region '{fake_region}' must not appear anymore"

    regions = {row["client_region"] for row in body}
    assert regions == {cdn_module.REGIONS_META["TH"]["name"], cdn_module.REGIONS_META["ASIA"]["name"]}
    for row in body:
        assert row["online"] is True
        assert isinstance(row["edge_ms"], int)


def test_latency_zero_origin_account_gets_empty_list_not_fake_data(
    client: TestClient, register_user, auth_header
):
    register_user(email="cdn-lat-bootstrap@example.com", username="cdn_lat_bootstrap")
    viewer = register_user(email="cdn-lat-zero@example.com", username="cdn_lat_zero", role="viewer")

    resp = client.get("/api/cdn/latency", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    assert resp.json() == []


# ------------------------------------------------- /logs/ingest IP gate

def test_known_edge_forwarder_ips_includes_both_real_edges_not_just_th():
    """2026-09-20: this set only ever listed edge-th's IP -- edge-asia's
    forwarder, if and when it runs, would hit the exact same 404-forever
    failure mode edge-th's did before this endpoint existed at all (see
    the comment above _KNOWN_EDGE_FORWARDER_IPS). Derived from
    REGIONS_META now instead of a second hardcoded literal."""
    assert cdn_module.REGIONS_META["TH"]["ip"] in cdn_module._KNOWN_EDGE_FORWARDER_IPS
    assert cdn_module.REGIONS_META["ASIA"]["ip"] in cdn_module._KNOWN_EDGE_FORWARDER_IPS
    # MAIN is Main itself, not an edge -- it must never be treated as a
    # trusted external log-forwarding source.
    assert cdn_module.REGIONS_META["MAIN"]["ip"] not in cdn_module._KNOWN_EDGE_FORWARDER_IPS
