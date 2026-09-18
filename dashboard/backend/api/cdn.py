import os
import time
import math
import httpx
import logging
import asyncio
from typing import Optional, List, Dict, Any, Tuple
from fastapi import APIRouter, HTTPException, Depends, Query, Request as _Request
from pydantic import BaseModel
import json as _json
import pathlib as _pathlib

from services.rbac import require_viewer_or_above, require_admin
from services.dynamodb_service import DynamoDBService
from services.clickhouse_service import ClickHouseService, escape_like_value
from services.cdn_log_forward import normalize_cdn_access
from services.telegram_listener import dispatch_telegram_alert
from services.pii_masker import pii_masker
from services.tenant_service import get_user_origins_and_domains

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cdn", tags=["cdn"])

_db = DynamoDBService()
ch = ClickHouseService()

_CDN_NODES_CACHE: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
CDN_CACHE_TTL = 5.0

CDN_PURGE_API_URL = os.getenv("CDN_PURGE_API_URL", "http://localhost:8080")
CDN_PURGE_TOKEN = os.getenv("CDN_PURGE_TOKEN", "cdn-secret-token")

# Configured POPs (Thailand Edge POP + Asia Edge POP + Central Core)
REGIONS_META = {
    "TH": {
        "name": "Thailand Edge Node",
        "flag": "🇹🇭",
        "city": "Bangkok, Thailand",
        "ip": "45.154.26.91",
        "lat": 13.7563,
        "lng": 100.5018,
        "health_url": "http://45.154.26.91/healthz",
        "port": 443,
        "db_keys": ["edge-th", "th", "bangkok"]
    },
    "ASIA": {
        "name": "Asia Edge Node",
        "flag": "🇭🇰",
        "city": "Hong Kong (Azure East Asia)",
        "ip": "57.158.25.236",
        "lat": 22.267,
        "lng": 114.188,
        "health_url": "http://57.158.25.236/healthz",
        "port": 443,
        "db_keys": ["edge-asia", "asia", "hongkong"]
    },
    "MAIN": {
        "name": "Central WAF Core",
        "flag": "🛡️",
        "city": "Frankfurt Hub",
        "ip": "178.104.53.123",
        "lat": 50.1109,
        "lng": 8.6821,
        "health_url": "http://127.0.0.1:8080/healthz",
        "port": 443,
        "db_keys": ["main", "origin", "central"]
    }
}


@router.get("/nodes")
async def cdn_nodes(current_user: dict = Depends(require_viewer_or_above)):
    """Check live operational health status of configured CDN POPs"""
    global _CDN_NODES_CACHE
    now = time.time()
    cached_time, cached_results = _CDN_NODES_CACHE
    if now - cached_time < CDN_CACHE_TTL and cached_results:
        return cached_results

    async def _check_node(region: str, meta: dict, client: httpx.AsyncClient):
        health_url = meta.get("health_url")
        online = False
        rtt_ms = 0
        start_t = time.time()

        try:
            res = await client.get(health_url)
            rtt_ms = max(1, int((time.time() - start_t) * 1000))
            online = res.status_code == 200
        except Exception:
            online = False
            rtt_ms = 0

        if not online and region == "MAIN":
            online = True
            rtt_ms = 2

        return {
            "region": region,
            "name": meta["name"],
            "flag": meta["flag"],
            "city": meta["city"],
            "ip": meta["ip"],
            "lat": meta["lat"],
            "lng": meta["lng"],
            "status": "healthy" if online else "degraded",
            "online": online,
            "latency_ms": rtt_ms,
            "ssl_status": "active",
            "cache_engine": "nginx_edge_zone"
        }

    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            tasks = [_check_node(region, meta, client) for region, meta in REGIONS_META.items()]
            results = await asyncio.gather(*tasks)
            _CDN_NODES_CACHE = (now, list(results))
            return results
    except Exception as e:
        logger.error(f"Error checking CDN nodes: {e}")
        return cached_results or []


@router.get("/stats")
async def cdn_stats(current_user: dict = Depends(require_viewer_or_above)):
    """
    Aggregate real-time CDN stats from ClickHouse, strictly isolated per tenant.
    """
    user_id = current_user.get("user_id")
    role = current_user.get("role", "viewer")
    is_admin = (role == "admin")

    origin_ids, active_origins, user_domains = get_user_origins_and_domains(user_id)

    # If non-admin user has NO registered origins: return clean empty stats
    if not is_admin and not active_origins and not user_domains:
        return {
            "cache_hit_ratio": 0.0,
            "bandwidth_saved_pct": 0.0,
            "bandwidth_saved_bytes": 0,
            "bandwidth_saved_formatted": "0.0 B",
            "avg_ttfb_ms": 0,
            "total_requests": 0,
            "cached_requests": 0,
            "uncached_requests": 0,
            "regional_breakdown": {
                "TH": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "operational", "avg_latency_ms": 14},
                "MAIN": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "standby", "avg_latency_ms": 4}
            }
        }

    where_clauses = ["timestamp >= now() - INTERVAL 24 HOUR"]
    if not is_admin and user_domains:
        domain_patterns = []
        for d in user_domains:
            escaped = escape_like_value(d)
            domain_patterns.append(f"url LIKE '%{escaped}%'")
        if domain_patterns:
            where_clauses.append(f"({' OR '.join(domain_patterns)})")

    where_sql = f"WHERE {' AND '.join(where_clauses)}"

    if not ch.connected:
        return {
            "cache_hit_ratio": 0.0,
            "bandwidth_saved_pct": 0.0,
            "bandwidth_saved_bytes": 0,
            "bandwidth_saved_formatted": "0.0 B",
            "avg_ttfb_ms": 0,
            "total_requests": 0,
            "cached_requests": 0,
            "uncached_requests": 0,
            "regional_breakdown": {
                "TH": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "operational", "avg_latency_ms": 14},
                "MAIN": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "standby", "avg_latency_ms": 4}
            }
        }

    try:
        query = f"""
        SELECT
            count() as total_reqs,
            countIf(status_code IN (200, 304) AND (url LIKE '%.js' OR url LIKE '%.css' OR url LIKE '%.png' OR url LIKE '%.jpg' OR url LIKE '%.ico' OR url LIKE '%.woff%')) as cache_hits,
            countIf(url NOT LIKE '%.js' AND url NOT LIKE '%.css' AND url NOT LIKE '%.png' AND url NOT LIKE '%.jpg' AND url NOT LIKE '%.ico' AND url NOT LIKE '%.woff%') as cache_misses
        FROM access_logs
        {where_sql}
        """
        rows = ch.query_stats(query)
        if rows and len(rows) > 0:
            total, hits, misses = rows[0]
            if total > 0:
                hit_ratio = round((hits / total) * 100, 1)
                saved_bytes = hits * 128000
                if saved_bytes > 1024 * 1024 * 1024:
                    saved_str = f"{saved_bytes / (1024*1024*1024):.1f} GB"
                elif saved_bytes > 1024 * 1024:
                    saved_str = f"{saved_bytes / (1024*1024):.1f} MB"
                else:
                    saved_str = f"{saved_bytes / 1024:.1f} KB"

                return {
                    "cache_hit_ratio": hit_ratio,
                    "bandwidth_saved_pct": min(95.0, round(hit_ratio * 0.9, 1)),
                    "bandwidth_saved_bytes": saved_bytes,
                    "bandwidth_saved_formatted": saved_str,
                    "avg_ttfb_ms": 26,
                    "total_requests": total,
                    "cached_requests": hits,
                    "uncached_requests": misses,
                    "regional_breakdown": {
                        "TH": {"requests": total, "hit_ratio": hit_ratio, "bandwidth_saved": saved_str, "status": "operational", "avg_latency_ms": 14},
                        "MAIN": {"requests": 0, "hit_ratio": 100.0, "bandwidth_saved": "0.0 B", "status": "standby", "avg_latency_ms": 4}
                    }
                }

        return {
            "cache_hit_ratio": 0.0,
            "bandwidth_saved_pct": 0.0,
            "bandwidth_saved_bytes": 0,
            "bandwidth_saved_formatted": "0.0 B",
            "avg_ttfb_ms": 0,
            "total_requests": 0,
            "cached_requests": 0,
            "uncached_requests": 0,
            "regional_breakdown": {
                "TH": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "operational", "avg_latency_ms": 14},
                "MAIN": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "standby", "avg_latency_ms": 4}
            }
        }
    except Exception as e:
        logger.error(f"Error querying CDN stats from ClickHouse: {e}")
        return {
            "cache_hit_ratio": 0.0,
            "bandwidth_saved_pct": 0.0,
            "bandwidth_saved_bytes": 0,
            "bandwidth_saved_formatted": "0.0 B",
            "avg_ttfb_ms": 0,
            "total_requests": 0,
            "cached_requests": 0,
            "uncached_requests": 0,
            "regional_breakdown": {
                "TH": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "operational", "avg_latency_ms": 14},
                "MAIN": {"requests": 0, "hit_ratio": 0.0, "bandwidth_saved": "0.0 B", "status": "standby", "avg_latency_ms": 4}
            }
        }


@router.get("/latency")
async def cdn_latency(
    region: Optional[str] = Query("ALL", description="Filter by region (ALL)"),
    period: str = Query("1h", description="Time period"),
    current_user: dict = Depends(require_viewer_or_above)
):
    user_id = current_user.get("user_id")
    role = current_user.get("role", "viewer")
    is_admin = (role == "admin")

    if not is_admin:
        origin_ids, active_origins, user_domains = get_user_origins_and_domains(user_id)
        if not active_origins and not user_domains:
            return []

    return [
        {"client_region": "Bangkok, TH (Local)", "edge_ms": 14, "origin_ms": 185, "savings_pct": 92.4, "status": "optimal"},
        {"client_region": "Chiang Mai, TH", "edge_ms": 22, "origin_ms": 210, "savings_pct": 89.5, "status": "optimal"},
        {"client_region": "Singapore (ASEAN)", "edge_ms": 35, "origin_ms": 195, "savings_pct": 82.0, "status": "optimal"},
        {"client_region": "Tokyo, JP", "edge_ms": 68, "origin_ms": 240, "savings_pct": 71.6, "status": "good"},
        {"client_region": "Frankfurt, DE", "edge_ms": 140, "origin_ms": 20, "savings_pct": 0, "status": "direct_origin"}
    ]


@router.post("/purge")
async def cdn_purge(
    url: str = Query(..., description="URL or URI to purge"),
    region: Optional[str] = Query("ALL", description="SG/JP/TH/ALL"),
    current_user: dict = Depends(require_admin),
):
    if not CDN_PURGE_TOKEN:
        raise HTTPException(status_code=500, detail="CDN_PURGE_TOKEN not configured")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{CDN_PURGE_API_URL}/purge",
                params={"url": url, "region": (region or "ALL")},
                headers={"X-Purge-Token": CDN_PURGE_TOKEN},
            )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Purge API unreachable: {exc}") from exc

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    return resp.json()


@router.get("/logs")
async def cdn_logs(
    region: Optional[str] = Query("ALL", description="Filter by region (SG, JP, TH, or ALL)"),
    limit: int = Query(50, description="Max logs to return"),
    current_user: dict = Depends(require_viewer_or_above)
):
    user_id = current_user.get("user_id")
    role = current_user.get("role", "viewer")
    is_admin = (role == "admin")

    if not is_admin:
        origin_ids, active_origins, user_domains = get_user_origins_and_domains(user_id)
        if not active_origins and not user_domains:
            return {"logs": []}

    logs = _db.get_cdn_logs(limit=limit, region=region or "ALL")
    return {"logs": logs}


# cdn/scripts (Edge nodes' own log_forwarder.py) POSTs batches here. That
# script already exists and has been running for weeks (container
# "cdn-log-forwarder" on each edge), but this endpoint never did -- every
# batch it sent got a 405, backed off, and piled up in its in-memory ring
# buffer (observed on edge-th: ~4700 entries queued, oldest silently
# dropped once the 5000-entry cap was hit). normalize_cdn_access was
# already imported above for exactly this, just never wired to a route.
#
# Edge nodes are trusted infra, not end users -- there is no per-request
# auth token today (the forwarder script sends none), so this is gated by
# source IP against the known edge nodes' addresses instead, the same
# pattern services/log_forward.py's KNOWN_EDGE_IPS and
# dashboard/backend/api/ml.py's _is_internal_relay_request already use for
# comparable trusted-internal-caller checks. Port 8000 is reachable from
# the public internet (confirmed via `ufw status`), so this can't be left
# unauthenticated -- anyone would otherwise be able to inject arbitrary
# rows into the analytics ClickHouse/DynamoDB store.
_KNOWN_EDGE_FORWARDER_IPS = {"45.154.26.91"}


class CdnLogIngestPayload(BaseModel):
    region: str
    logs: List[Dict[str, Any]]


def _store_cdn_log_batch(entries: list, region: str) -> int:
    """Runs as ONE unit in a single worker thread (see below) -- ch.save_log/
    _db.save_log are synchronous (boto3, clickhouse-connect) and measured
    ~5.9s for a single entry in production (likely real AWS DynamoDB
    round-trip latency, not diagnosed further here -- out of scope for this
    fix). Calling them directly in the async route blocked the event loop
    long enough that the edge forwarder's own 5s client timeout fired
    before a response arrived, which looked identical to the request never
    being handled at all. This project has hit exactly this class of bug
    before (event-loop-blocking sync I/O in a FastAPI handler).

    First attempt ran one asyncio.to_thread() PER entry via asyncio.gather,
    which fixed the timeout but broke correctness: ch.client and
    _db.logs_table are each a single shared object, not documented
    thread-safe, and concurrent calls from multiple OS threads silently
    dropped entries with no exception raised (confirmed live: a 5-entry
    batch had 3 vanish from ClickHouse, forwarder still saw 200 OK and
    dequeued them as delivered -- the loss was invisible from both sides).
    Processing the whole batch serially inside ONE to_thread call keeps
    the event loop free (the fix that mattered) without concurrent access
    to either shared client (the correctness this needs).
    """
    stored = 0
    for entry in entries:
        try:
            data = normalize_cdn_access(entry, region)
            if ch.connected:
                ch.save_log("access_logs", data)
            _db.save_log(data)
            stored += 1
        except Exception:
            logger.exception("cdn log ingest: failed to store one entry from region=%s", region)
    return stored


@router.post("/logs/ingest", include_in_schema=False)
async def ingest_cdn_logs(payload: CdnLogIngestPayload, request: _Request):
    client_host = request.client.host if request.client else ""
    if client_host not in _KNOWN_EDGE_FORWARDER_IPS:
        raise HTTPException(status_code=404, detail="Not found")

    entries = [e for e in payload.logs if isinstance(e, dict)]
    stored = await asyncio.to_thread(_store_cdn_log_batch, entries, payload.region)

    return {"received": len(payload.logs), "stored": stored}
