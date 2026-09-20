"""
Scenario: 2026-09-22 (overnight session) -- building a public, unauthenticated
status page. REGIONS_META (api/cdn.py) and _check_node()'s real return value
carry real edge IPs (45.154.26.91, 57.158.25.236, 178.104.53.123), a
loopback health_url, lat/lng coordinates precise enough to be a real
address, and raw exception text on failure. An unauthenticated endpoint
that ever passed that through wholesale would be a straightforward recon
leak -- reviewed before writing this (advisor call), the fix is: build the
public payload by naming each field explicitly, never by forwarding a
health-check result. These tests are the actual proof of that, not a
reading of the code -- the same principle scripts/smoke_test.sh's T5 (no
secrets in the bundle) already enforces for a different leak class, applied
here at the endpoint-payload level with its own smoke_test check added
alongside it.

Also: _probe_all_regions() is real network I/O and must never run on every
hit of an unauthenticated endpoint (amplification vector) -- get_public_
status_snapshot() caches for 30s with a lock, same pattern as api/domains.py's
_ssl_allowed_set().
"""
import asyncio
import datetime as dt

import pytest

import services.public_status as public_status


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# build_public_snapshot: the field whitelist itself
# ---------------------------------------------------------------------------

_REAL_SHAPED_CHECK_RESULT = {
    "region": "TH",
    "name": "Thailand Edge Node",
    "flag": "🇹🇭",
    "city": "Bangkok, Thailand",
    "ip": "45.154.26.91",
    "lat": 13.7563,
    "lng": 100.5018,
    "status": "healthy",
    "online": True,
    "latency_ms": 42,
    "ssl_status": "port_open",
    "cache_engine": "nginx_edge_zone",
}


def test_build_public_snapshot_never_leaks_an_ip_address():
    snapshot = public_status.build_public_snapshot({"TH": _REAL_SHAPED_CHECK_RESULT})
    blob = str(snapshot)
    assert "45.154.26.91" not in blob


def test_build_public_snapshot_never_leaks_lat_lng_or_internal_fields():
    snapshot = public_status.build_public_snapshot({"TH": _REAL_SHAPED_CHECK_RESULT})
    component = snapshot["components"][0]
    assert set(component.keys()) == {"id", "name", "status"}


def test_build_public_snapshot_marks_an_offline_node_degraded():
    offline = {**_REAL_SHAPED_CHECK_RESULT, "online": False, "status": "degraded"}
    snapshot = public_status.build_public_snapshot({"TH": offline})
    assert snapshot["components"][0]["status"] == "degraded"
    assert snapshot["overall_status"] == "degraded"


def test_build_public_snapshot_is_operational_only_when_every_component_is():
    healthy = _REAL_SHAPED_CHECK_RESULT
    offline = {**_REAL_SHAPED_CHECK_RESULT, "online": False}
    snapshot = public_status.build_public_snapshot({"TH": healthy, "ASIA": offline})
    assert snapshot["overall_status"] == "degraded"

    snapshot_all_up = public_status.build_public_snapshot({"TH": healthy, "ASIA": healthy})
    assert snapshot_all_up["overall_status"] == "operational"


def test_build_public_snapshot_handles_a_failed_probe_as_unknown_not_a_crash():
    # A probe that raised (network error, timeout) lands here as an
    # Exception instance (asyncio.gather(..., return_exceptions=True)) or
    # None -- must never leak the exception's own text (which can include
    # the IP/hostname it failed to reach).
    snapshot = public_status.build_public_snapshot({"TH": ConnectionError("connect to 45.154.26.91 failed")})
    component = snapshot["components"][0]
    assert component["status"] == "unknown"
    assert "45.154.26.91" not in str(component)


def test_build_public_snapshot_never_leaks_the_real_region_meta_health_url():
    snapshot = public_status.build_public_snapshot({"MAIN": {**_REAL_SHAPED_CHECK_RESULT, "ip": "178.104.53.123"}})
    assert "127.0.0.1:8080" not in str(snapshot)
    assert "178.104.53.123" not in str(snapshot)


# ---------------------------------------------------------------------------
# get_public_status_snapshot: caching -- must not probe on every call
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_snapshot_cache():
    public_status._SNAPSHOT_CACHE = None
    public_status._SNAPSHOT_AT = 0.0
    yield
    public_status._SNAPSHOT_CACHE = None
    public_status._SNAPSHOT_AT = 0.0


def test_get_public_status_snapshot_only_probes_once_within_the_ttl():
    call_count = {"n": 0}

    async def fake_probe():
        call_count["n"] += 1
        return {"TH": _REAL_SHAPED_CHECK_RESULT}

    t0 = 1000.0
    _run(public_status.get_public_status_snapshot(probe=fake_probe, now_monotonic=t0))
    _run(public_status.get_public_status_snapshot(probe=fake_probe, now_monotonic=t0 + 5))
    _run(public_status.get_public_status_snapshot(probe=fake_probe, now_monotonic=t0 + 29))

    assert call_count["n"] == 1


def test_get_public_status_snapshot_probes_again_once_the_ttl_elapses():
    call_count = {"n": 0}

    async def fake_probe():
        call_count["n"] += 1
        return {"TH": _REAL_SHAPED_CHECK_RESULT}

    t0 = 1000.0
    _run(public_status.get_public_status_snapshot(probe=fake_probe, now_monotonic=t0))
    _run(public_status.get_public_status_snapshot(probe=fake_probe, now_monotonic=t0 + 31))

    assert call_count["n"] == 2


def test_get_public_status_snapshot_serves_stale_on_a_transient_probe_failure():
    async def good_probe():
        return {"TH": _REAL_SHAPED_CHECK_RESULT}

    async def broken_probe():
        raise RuntimeError("all edges unreachable")

    t0 = 1000.0
    first = _run(public_status.get_public_status_snapshot(probe=good_probe, now_monotonic=t0))
    second = _run(public_status.get_public_status_snapshot(probe=broken_probe, now_monotonic=t0 + 31))

    assert second == first  # stale snapshot served, not an exception, not empty


# ---------------------------------------------------------------------------
# history recording / reading (uptime bars)
# ---------------------------------------------------------------------------

def test_record_history_sample_increments_sample_and_healthy_counts(db):
    now = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    components = [{"id": "th", "name": "Thailand", "status": "operational"}]
    public_status._record_history_sample(components, db=db, now=now)
    public_status._record_history_sample(components, db=db, now=now)

    row = db.status_history_table.get_item(Key={"component_id": "th", "date_bucket": "2026-09-22"})["Item"]
    assert row["sample_count"] == 2
    assert row["healthy_count"] == 2


def test_record_history_sample_does_not_count_a_degraded_sample_as_healthy(db):
    now = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    public_status._record_history_sample(
        [{"id": "th", "name": "Thailand", "status": "degraded"}], db=db, now=now,
    )
    row = db.status_history_table.get_item(Key={"component_id": "th", "date_bucket": "2026-09-22"})["Item"]
    assert row["sample_count"] == 1
    assert row["healthy_count"] == 0


def test_get_uptime_history_computes_percentage_from_recorded_samples(db):
    now = dt.datetime(2026, 9, 22, 12, 0, tzinfo=dt.timezone.utc)
    for _ in range(3):
        public_status._record_history_sample(
            [{"id": "th", "name": "Thailand", "status": "operational"}], db=db, now=now,
        )
    public_status._record_history_sample(
        [{"id": "th", "name": "Thailand", "status": "degraded"}], db=db, now=now,
    )

    history = public_status.get_uptime_history(days=7, db=db, now=now)
    today = [d for d in history["th"] if d["date"] == "2026-09-22"][0]
    assert today["uptime_pct"] == 75.0


def test_get_uptime_history_reports_none_for_a_day_with_no_samples(db):
    now = dt.datetime(2026, 9, 22, 12, 0, tzinfo=dt.timezone.utc)
    history = public_status.get_uptime_history(days=3, db=db, now=now)
    assert all(d["uptime_pct"] is None for d in history["th"])
