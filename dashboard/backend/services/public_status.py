"""Public, unauthenticated system status ("status page") -- reviewed as a
security change, not a UI feature, before writing this (2026-09-22
overnight session, advisor call).

Two hard constraints that decide this module's shape:

1. api/cdn.py's REGIONS_META and _check_node()'s real return value carry
   real edge IPs (45.154.26.91, 57.158.25.236, 178.104.53.123), a loopback
   health_url, precise lat/lng, and raw exception text on failure. This
   module never forwards that wholesale -- build_public_snapshot() names
   every field it emits (id, name, status only). tests/test_public_status.py
   asserts on this directly (no IP/hostname anywhere in the output), not
   just on the code reading correctly.

2. This endpoint has no auth, so a naive implementation that probes the
   edges on every request is a request-amplification vector (an attacker
   hitting /api/status/public in a loop makes this backend hit every edge
   in a loop). get_public_status_snapshot() caches for 30s behind a lock,
   the exact pattern api/domains.py's _ssl_allowed_set() already uses for
   the same reason.
"""
import asyncio
import datetime as dt
import os
import time
from typing import Optional, Callable, Dict, Any, List

from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

SNAPSHOT_TTL_SECONDS = 30.0
HISTORY_SAMPLE_INTERVAL_SECONDS = int(os.getenv("STATUS_HISTORY_SAMPLE_INTERVAL_SECONDS", "300"))
HISTORY_RETENTION_DAYS = int(os.getenv("STATUS_HISTORY_RETENTION_DAYS", "400"))
DEFAULT_HISTORY_DAYS = 90

# Public-facing labels only -- deliberately not api/cdn.py's REGIONS_META
# dict (real city/IP/health_url/lat/lng). A status page names regions and
# health; nothing here should help anyone target an edge directly.
PUBLIC_REGION_LABELS = {
    "TH": "Thailand Edge",
    "ASIA": "Asia Pacific Edge",
    "MAIN": "Core / Control Plane",
}

_SNAPSHOT_CACHE: Optional[dict] = None
_SNAPSHOT_AT = 0.0
_SNAPSHOT_LOCK = asyncio.Lock()


def _whitelist_component(region: str, check_result: Any) -> Dict[str, str]:
    name = PUBLIC_REGION_LABELS.get(region, region)
    if not isinstance(check_result, dict):
        # A failed probe lands here as an Exception instance or None --
        # never render str(exception), which can carry the IP/hostname it
        # failed to reach.
        return {"id": region.lower(), "name": name, "status": "unknown"}
    online = bool(check_result.get("online"))
    return {
        "id": region.lower(),
        "name": name,
        "status": "operational" if online else "degraded",
    }


def build_public_snapshot(raw_results_by_region: Dict[str, Any], now: Optional[dt.datetime] = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    components = [_whitelist_component(region, result) for region, result in raw_results_by_region.items()]
    overall = "operational" if components and all(c["status"] == "operational" for c in components) else (
        "unknown" if not components else "degraded"
    )
    return {
        "overall_status": overall,
        "components": components,
        "checked_at": now.isoformat(),
    }


async def _probe_all_regions() -> Dict[str, Any]:
    # Local import: avoids a module-load-time dependency from
    # services/public_status.py on api/cdn.py (mirrors the existing
    # function-scoped-import convention services/origin_service.py already
    # uses for `from api.tunnels import get_proxy_owner`).
    import httpx
    from api.cdn import REGIONS_META, _check_node

    async with httpx.AsyncClient(timeout=1.2) as client:
        tasks = [_check_node(region, meta, client) for region, meta in REGIONS_META.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    return dict(zip(REGIONS_META.keys(), results))


async def get_public_status_snapshot(
    probe: Optional[Callable] = None,
    now_monotonic: Optional[float] = None,
) -> dict:
    global _SNAPSHOT_CACHE, _SNAPSHOT_AT
    probe = probe or _probe_all_regions
    now = now_monotonic if now_monotonic is not None else time.monotonic()

    if _SNAPSHOT_CACHE and (now - _SNAPSHOT_AT) < SNAPSHOT_TTL_SECONDS:
        return _SNAPSHOT_CACHE

    async with _SNAPSHOT_LOCK:
        now = now_monotonic if now_monotonic is not None else time.monotonic()
        if _SNAPSHOT_CACHE and (now - _SNAPSHOT_AT) < SNAPSHOT_TTL_SECONDS:
            return _SNAPSHOT_CACHE
        try:
            raw = await probe()
            _SNAPSHOT_CACHE = build_public_snapshot(raw)
            _SNAPSHOT_AT = now
        except Exception as e:
            print(f"[public_status] snapshot refresh failed, serving stale: {e}")

    return _SNAPSHOT_CACHE or build_public_snapshot({})


def _record_history_sample(components: List[dict], db=None, now: Optional[dt.datetime] = None) -> None:
    _db = db if db is not None else globals()["db"]
    now = now or dt.datetime.now(dt.timezone.utc)
    date_bucket = now.strftime("%Y-%m-%d")
    expires_at = int((now + dt.timedelta(days=HISTORY_RETENTION_DAYS)).timestamp())

    for c in components:
        healthy = 1 if c.get("status") == "operational" else 0
        _db.status_history_table.update_item(
            Key={"component_id": c["id"], "date_bucket": date_bucket},
            UpdateExpression="SET #exp = :exp, #name = :name ADD #sc :one, #hc :healthy",
            ExpressionAttributeNames={
                "#exp": "expires_at",
                "#name": "name",
                "#sc": "sample_count",
                "#hc": "healthy_count",
            },
            ExpressionAttributeValues={
                ":exp": expires_at,
                ":name": c.get("name", c["id"]),
                ":one": 1,
                ":healthy": healthy,
            },
        )


def get_uptime_history(days: int = DEFAULT_HISTORY_DAYS, db=None, now: Optional[dt.datetime] = None) -> Dict[str, list]:
    """Returns {component_id: [{"date": "YYYY-MM-DD", "uptime_pct": float|None}, ...]}
    for the last `days` days, oldest first. None means no samples were
    recorded that day (not "0% uptime")."""
    from boto3.dynamodb.conditions import Key

    _db = db if db is not None else globals()["db"]
    now = now or dt.datetime.now(dt.timezone.utc)
    dates = [(now - dt.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)]
    date_set = set(dates)

    result: Dict[str, list] = {}
    for region in PUBLIC_REGION_LABELS:
        cid = region.lower()
        rows_by_date = {}
        try:
            items = _db.status_history_table.query(
                KeyConditionExpression=Key("component_id").eq(cid)
            ).get("Items", [])
        except Exception as e:
            print(f"[public_status] history query failed for {cid}: {e}")
            items = []
        for item in items:
            d = item.get("date_bucket")
            if d in date_set and item.get("sample_count"):
                rows_by_date[d] = round(100 * item["healthy_count"] / item["sample_count"], 2)

        result[cid] = [{"date": d, "uptime_pct": rows_by_date.get(d)} for d in reversed(dates)]

    return result


async def public_status_history_worker():
    """Background loop: samples the live snapshot every
    HISTORY_SAMPLE_INTERVAL_SECONDS and rolls it into a daily
    sample_count/healthy_count counter per component -- mirrors
    services/dns_verification_worker.py's shape (try/except per tick so one
    bad sample never stops the loop)."""
    print("=" * 50)
    print("Starting Public Status History Worker...")
    print("=" * 50)

    while True:
        try:
            snapshot = await get_public_status_snapshot()
            _record_history_sample(snapshot["components"])
        except Exception as e:
            print(f"[public_status] history sample failed: {e}")
        await asyncio.sleep(HISTORY_SAMPLE_INTERVAL_SECONDS)
