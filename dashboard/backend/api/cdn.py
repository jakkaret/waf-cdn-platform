import os
from typing import Optional


import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from services.rbac import require_admin, require_viewer_or_above
from services.dynamodb_service import DynamoDBService

router = APIRouter(prefix="/api/cdn", tags=["cdn"])

CDN_STATS_URL = os.getenv("CDN_STATS_URL", "http://cdn-stats:9090/metrics")
CDN_PURGE_API_URL = os.getenv("CDN_PURGE_API_URL", "http://localhost:8090")
CDN_PURGE_TOKEN = os.getenv("CDN_PURGE_TOKEN", "cdn-secret-token")

REGIONS_META = {
    "SG": {"name": "Singapore", "flag": "🇸🇬", "lat": 1.3521, "lng": 103.8198},
    "JP": {"name": "Japan", "flag": "🇯🇵", "lat": 35.6762, "lng": 139.6503},
    "TH": {"name": "Thailand", "flag": "🇹🇭", "lat": 13.7563, "lng": 100.5018},
}

EDGE_PORTS = {
    "SG": 8081,
    "JP": 8082,
    "TH": 8086,
}


async def _fetch_stats() -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(CDN_STATS_URL)
            r.raise_for_status()
            return r.json()
    except Exception:
        return _mock_stats()


def _mock_stats() -> dict:
    mock = {}
    base_hits = {"SG": 120, "JP": 105, "TH": 160}
    base_miss = {"SG": 20, "JP": 22, "TH": 25}
    base_bypass = {"SG": 8, "JP": 6, "TH": 11}

    total_all = {
        "cache_hit": 0,
        "cache_miss": 0,
        "cache_bypass": 0,
        "request_count": 0,
        "status_2xx": 0,
        "blocked_count": 0,
        "status_5xx": 0,
    }

    for region in EDGE_PORTS:
        h = base_hits[region]
        m = base_miss[region]
        b = base_bypass[region]
        total = h + m + b
        mock[region] = {
            "region": region,
            "cache_hit": h,
            "cache_miss": m,
            "cache_bypass": b,
            "request_count": total,
            "status_2xx": int(total * 0.93),
            "blocked_count": int(total * 0.05),
            "status_5xx": int(total * 0.02),
            "avg_latency": {"SG": 13.1, "JP": 17.3, "TH": 10.4}[region],
        }
        for key in total_all:
            total_all[key] += mock[region].get(key, 0)

    mock["GLOBAL"] = {
        "region": "GLOBAL",
        **total_all,
        "avg_latency": 13.6, # approximate average
    }
    return mock


def _enrich(stats: dict) -> list:
    result = []
    for region, data in stats.items():
        if region == "GLOBAL":
            continue
        meta = REGIONS_META.get(region, {})
        result.append({**data, **meta, "port": EDGE_PORTS.get(region)})
    return result


@router.get("/stats")
async def cdn_stats(current_user: dict = Depends(require_viewer_or_above)):
    raw = await _fetch_stats()
    nodes = _enrich(raw)
    return nodes


@router.get("/stats/{region}")
async def cdn_stats_region(region: str, current_user: dict = Depends(require_viewer_or_above)):
    region = region.upper()
    if region not in EDGE_PORTS:
        raise HTTPException(status_code=404, detail=f"Region {region} not found")

    raw = await _fetch_stats()
    data = raw.get(region)
    if not data:
        raise HTTPException(status_code=404, detail="Stats not available yet")

    meta = REGIONS_META.get(region, {})
    return {**data, **meta, "port": EDGE_PORTS[region]}


@router.get("/nodes")
async def cdn_nodes(current_user: dict = Depends(require_viewer_or_above)):
    results = []

    async with httpx.AsyncClient(timeout=3.0) as client:
        for region, port in EDGE_PORTS.items():
            meta = REGIONS_META.get(region, {})
            try:
                r = await client.get(f"http://localhost:{port}/healthz")
                online = r.status_code == 200
                health_data = r.json() if online else {}
            except Exception:
                online = False
                health_data = {}

            results.append(
                {
                    "region": region,
                    "name": meta.get("name", region),
                    "flag": meta.get("flag", "🌐"),
                    "lat": meta.get("lat"),
                    "lng": meta.get("lng"),
                    "port": port,
                    "status": "online" if online else "offline",
                    **health_data,
                }
            )

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
    db = DynamoDBService()
    # Fetch logs from DynamoDB
    all_logs = db.get_logs(limit=2000)
    
    # Filter for CDN logs only
    cdn_logs_list = [log for log in all_logs if log.get("source") == "cdn"]
    
    # Filter by region if specified
    if region and region.upper() != "ALL":
        cdn_logs_list = [log for log in cdn_logs_list if log.get("region") == region.upper()]
        
    # Sort by timestamp descending
    cdn_logs_list.sort(key=lambda x: int(x.get("timestamp", 0)), reverse=True)
    
    return {"logs": cdn_logs_list[:limit]}


@router.get("/latency")
async def cdn_latency(
    region: Optional[str] = Query("ALL", description="Filter by region (SG, JP, TH, or ALL)"),
    period: str = Query("1h", description="Time period (currently unused, fetches recent logs)"),
    current_user: dict = Depends(require_viewer_or_above)
):
    db = DynamoDBService()
    # Fetch recent logs (simulate last 1h with max limit)
    all_logs = db.get_logs(limit=2000)
    
    cdn_logs = [log for log in all_logs if log.get("source") == "cdn"]
    
    if region and region.upper() != "ALL":
        cdn_logs = [log for log in cdn_logs if log.get("region") == region.upper()]
        
    # Group by region
    from collections import defaultdict
    from datetime import datetime
    
    region_latencies = defaultdict(list)
    timeseries_data = defaultdict(lambda: {"SG": 0, "JP": 0, "TH": 0, "_count": {"SG": 0, "JP": 0, "TH": 0}})
    
    for log in cdn_logs:
        r = log.get("region", "UNKNOWN")
        lat = log.get("latency_ms", 0)
        region_latencies[r].append(lat)
        
        # Simple grouping by minute for timeseries (using timestamp)
        ts = int(log.get("timestamp", 0))
        if ts > 0:
            dt = datetime.fromtimestamp(ts)
            time_bucket = dt.strftime("%H:%M") # group by minute
            timeseries_data[time_bucket][r] += lat
            timeseries_data[time_bucket]["_count"][r] += 1
            
    summary = []
    for r, latencies in region_latencies.items():
        if not latencies:
            continue
        latencies.sort()
        n = len(latencies)
        avg_ms = int(sum(latencies) / n)
        p95_ms = latencies[int(n * 0.95)] if n > 0 else 0
        p99_ms = latencies[int(n * 0.99)] if n > 0 else 0
        summary.append({
            "region": r,
            "avg_ms": avg_ms,
            "p95_ms": p95_ms,
            "p99_ms": p99_ms
        })
        
    # Format timeseries
    timeseries = []
    for time_bucket, data in sorted(timeseries_data.items()):
        point = {"time": time_bucket}
        for r in ["SG", "JP", "TH"]:
            count = data["_count"][r]
            point[r] = int(data[r] / count) if count > 0 else 0
        timeseries.append(point)
        
    # Limit timeseries points to last 60 minutes if there are many
    timeseries = timeseries[-60:]
        
    return {
        "summary": summary,
        "timeseries": timeseries
    }

