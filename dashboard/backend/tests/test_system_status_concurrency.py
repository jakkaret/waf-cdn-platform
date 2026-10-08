"""F-001: /api/system/status must not block the event loop.

Probes are patched to sleep; the endpoint must overlap them (total ~= one
probe, not N) and concurrent requests must not serialize behind each other.
"""
import asyncio
import time

import httpx
import pytest

import main
from services.rbac import require_viewer_or_above

PROBE_DELAY = 0.3


@pytest.fixture
def status_app(monkeypatch):
    def slow_port_open(port, host="127.0.0.1"):
        time.sleep(PROBE_DELAY)  # blocking, like the real connect_ex
        return port != 7000  # frps offline, rest online

    def slow_db_status():
        time.sleep(PROBE_DELAY)
        return "ACTIVE"

    async def fake_nodes(current_user=None):
        return [{"region": "TH", "status": "healthy", "port": 443,
                 "latency_ms": 12, "health": {"ok": True}}]

    import api.cdn as cdn_mod
    monkeypatch.setattr(main, "_port_open", slow_port_open)
    monkeypatch.setattr(main, "_dynamodb_table_status", slow_db_status)
    monkeypatch.setattr(cdn_mod, "cdn_nodes", fake_nodes)
    main.app.dependency_overrides[require_viewer_or_above] = lambda: {"username": "t", "role": "viewer"}
    yield main.app
    main.app.dependency_overrides.pop(require_viewer_or_above, None)


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def test_status_shape(status_app):
    async def go():
        async with _client(status_app) as c:
            return await c.get("/api/system/status")
    r = asyncio.run(go())
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"db", "services", "cdn_nodes", "workers", "system"}
    assert body["db"] == {"status": "online", "detail": "DynamoDB reachable"}
    assert list(body["services"]) == ["dashboard_api", "waf_nginx", "redis",
                                      "clickhouse", "frps", "control_api"]
    assert body["services"]["redis"] == {"status": "online", "port": 6379,
                                         "desc": "rate-limit and cache store"}
    assert body["services"]["frps"]["status"] == "offline"
    assert body["cdn_nodes"] == [{"region": "TH", "status": "healthy", "port": 443,
                                  "latency_ms": 12, "health": {"ok": True}}]
    assert body["workers"]["tunnel_gatekeeper"]["status"] == "stopped"
    assert body["workers"]["log_pipeline"]["status"] == "running"
    assert set(body["system"]) == {"disk_total_gb", "disk_used_gb", "disk_free_gb",
                                   "disk_used_percent", "load_average"}


def test_status_probes_overlap(status_app):
    """6 port probes + DB probe, each 0.3s: sequential would be >= 2.1s."""
    async def go():
        async with _client(status_app) as c:
            t0 = time.perf_counter()
            r = await c.get("/api/system/status")
            return r, time.perf_counter() - t0
    r, elapsed = asyncio.run(go())
    assert r.status_code == 200
    # ports run in parallel (~0.3) then DB (~0.3); allow slack, far below 2.1.
    assert elapsed < PROBE_DELAY * 3, elapsed


def test_concurrent_requests_do_not_serialize(status_app):
    """Event loop stays free: 4 simultaneous requests ~= one request."""
    async def go():
        async with _client(status_app) as c:
            t0 = time.perf_counter()
            rs = await asyncio.gather(*(c.get("/api/system/status") for _ in range(4)))
            return rs, time.perf_counter() - t0
    rs, elapsed = asyncio.run(go())
    assert all(r.status_code == 200 for r in rs)
    # Serialized would be 4 * ~0.6 = 2.4s; overlapped ~0.6s.
    assert elapsed < 1.5, elapsed
