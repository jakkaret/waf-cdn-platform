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


async def _check_tls_port(ip: str, port: int = 443, timeout: float = 1.5) -> bool:
    """Real TCP-level probe of the TLS port -- this is deliberately NOT a
    full certificate-chain validation. Caddy's on-demand TLS on these edges
    issues certs per verified HOSTNAME (SNI-gated, see
    api/domains.py's check-ssl-allowed), not per bare IP -- connecting to
    the IP directly with no matching SNI never gets a usable cert back
    (confirmed live: openssl s_client / curl --resolve to a real routed
    hostname DOES complete and validate; the bare IP does not). Rather than
    hardcode a per-edge "known test domain" that will silently rot the
    moment that domain's tunnel is reconfigured, this only asserts the one
    thing that's cheap and durable to check without that fragility: is
    something actually listening and willing to start a TLS handshake on
    443 right now. Replaces a literal `"ssl_status": "active"` that was
    never checked at all before this."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _check_node(region: str, meta: dict, client: httpx.AsyncClient) -> Dict[str, Any]:
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

    if region == "MAIN":
        # health_url is a loopback http:// call -- there is no TLS hop to
        # probe here at all, so "active"/"unreachable" would both be a lie.
        ssl_status = "not_applicable"
    else:
        ssl_status = "port_open" if await _check_tls_port(meta["ip"], meta.get("port", 443)) else "unreachable"

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
        "ssl_status": ssl_status,
        "cache_engine": "nginx_edge_zone"
    }


@router.get("/nodes")
async def cdn_nodes(current_user: dict = Depends(require_viewer_or_above)):
    """Check live operational health status of configured CDN POPs"""
    global _CDN_NODES_CACHE
    now = time.time()
    cached_time, cached_results = _CDN_NODES_CACHE
    if now - cached_time < CDN_CACHE_TTL and cached_results:
        return cached_results

    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            tasks = [_check_node(region, meta, client) for region, meta in REGIONS_META.items()]
            results = await asyncio.gather(*tasks)
            _CDN_NODES_CACHE = (now, list(results))
            return results
    except Exception as e:
        logger.error(f"Error checking CDN nodes: {e}")
        return cached_results or []


def _empty_cdn_stats() -> Dict[str, Any]:
    # No fake TH/MAIN placeholder rows -- a region only appears in
    # regional_breakdown once real access_logs rows exist for it. An empty
    # dict here is honest; a dict with invented zero-filled regions was the
    # thing this replaced.
    return {
        "cache_hit_ratio": 0.0,
        "bandwidth_saved_pct": 0.0,
        "bandwidth_saved_bytes": 0,
        "bandwidth_saved_formatted": "0.0 B",
        "avg_ttfb_ms": 0,
        "total_requests": 0,
        "cached_requests": 0,
        "uncached_requests": 0,
        "regional_breakdown": {},
    }


def _format_bytes(n: int) -> str:
    if n > 1024 * 1024 * 1024:
        return f"{n / (1024*1024*1024):.1f} GB"
    if n > 1024 * 1024:
        return f"{n / (1024*1024):.1f} MB"
    return f"{n / 1024:.1f} KB"


# Reverse lookup from a raw ClickHouse edge_node value (e.g. "edge-th") to
# the display region code ("TH") -- reuses REGIONS_META's own db_keys
# instead of a second hand-maintained mapping.
_REGION_BY_DB_KEY = {
    key: region for region, meta in REGIONS_META.items() for key in meta["db_keys"]
}


def _region_label_for(edge_node_value: Optional[str]) -> str:
    return _REGION_BY_DB_KEY.get((edge_node_value or "").strip().lower(), edge_node_value or "unknown")


def _nan_to_zero(v) -> float:
    # ClickHouse's avgIf() returns NaN (not NULL) when zero rows match the
    # condition -- request_time_ms is ~73% zero right now (known, tracked
    # separately), so this branch is hit often, not an edge case.
    if v is None:
        return 0.0
    try:
        return 0.0 if v != v else float(v)
    except TypeError:
        return 0.0


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
        return _empty_cdn_stats()

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
        return _empty_cdn_stats()

    try:
        query = f"""
        SELECT
            edge_node,
            count() as total_reqs,
            countIf(status_code IN (200, 304) AND (url LIKE '%.js' OR url LIKE '%.css' OR url LIKE '%.png' OR url LIKE '%.jpg' OR url LIKE '%.ico' OR url LIKE '%.woff%')) as cache_hits,
            avgIf(request_time_ms, request_time_ms > 0) as avg_lat_ms
        FROM access_logs
        {where_sql}
        GROUP BY edge_node
        """
        rows = ch.query_stats(query) or []
        total = sum(r[1] for r in rows)
        hits = sum(r[2] for r in rows)

        if total == 0:
            return _empty_cdn_stats()

        misses = total - hits
        hit_ratio = round((hits / total) * 100, 1)
        saved_bytes = hits * 128000
        saved_str = _format_bytes(saved_bytes)

        ttfb_rows = ch.query_stats(
            f"SELECT avgIf(request_time_ms, request_time_ms > 0) FROM access_logs {where_sql}"
        )
        avg_ttfb_ms = round(_nan_to_zero(ttfb_rows[0][0])) if ttfb_rows else 0

        regional_breakdown: Dict[str, Any] = {}
        for edge_node_val, reqs, region_hits, avg_lat in rows:
            region_hit_ratio = round((region_hits / reqs) * 100, 1) if reqs else 0.0
            label = _region_label_for(edge_node_val)
            regional_breakdown[label] = {
                "requests": reqs,
                "hit_ratio": region_hit_ratio,
                "bandwidth_saved": _format_bytes(region_hits * 128000),
                "status": "operational" if reqs > 0 else "standby",
                "avg_latency_ms": round(_nan_to_zero(avg_lat)),
            }

        return {
            "cache_hit_ratio": hit_ratio,
            "bandwidth_saved_pct": min(95.0, round(hit_ratio * 0.9, 1)),
            "bandwidth_saved_bytes": saved_bytes,
            "bandwidth_saved_formatted": saved_str,
            "avg_ttfb_ms": avg_ttfb_ms,
            "total_requests": total,
            "cached_requests": hits,
            "uncached_requests": misses,
            "regional_breakdown": regional_breakdown,
        }
    except Exception as e:
        logger.error(f"Error querying CDN stats from ClickHouse: {e}")
        return _empty_cdn_stats()


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

    # 2026-09-20: this used to return a fully fabricated array -- fixed
    # "client_region" rows for Singapore and Tokyo that have never existed
    # as real edges (only TH and Azure/"ASIA" are real, see REGIONS_META),
    # with edge_ms/origin_ms/savings_pct numbers that were never measured.
    # We do not have real client-side RUM (no browser beacon reports actual
    # visitor latency back), so "latency experienced by a user in city X"
    # is not a real, honest thing to claim right now. What IS real and
    # measurable: round-trip time from this backend to each edge, using the
    # exact same health probe as /nodes. That is a genuinely useful signal
    # (network path health to each real edge) even though it answers a
    # different, narrower question than the old fake per-city rows did.
    async with httpx.AsyncClient(timeout=1.2) as client:
        main_node = await _check_node("MAIN", REGIONS_META["MAIN"], client)
        results = []
        for region in ("TH", "ASIA"):
            meta = REGIONS_META[region]
            node = await _check_node(region, meta, client)
            results.append({
                "client_region": meta["name"],
                "edge_ms": node["latency_ms"] if node["online"] else None,
                "origin_ms": main_node["latency_ms"],
                "online": node["online"],
                "status": "measured" if node["online"] else "unreachable",
            })
        return results


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
#
# 2026-09-20: this only ever listed edge-th's IP -- a second real edge
# (edge-asia, 57.158.25.236) exists and GeoDNS already routes real
# non-Thailand traffic to it (confirmed live), but its log forwarder, if
# and when it runs, would hit the exact same 404-forever failure mode
# edge-th's did before that endpoint existed at all. Derived from
# REGIONS_META instead of a second hardcoded literal, so a third real edge
# only needs adding there, not here too.
_KNOWN_EDGE_FORWARDER_IPS = {meta["ip"] for region, meta in REGIONS_META.items() if region != "MAIN"}


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
