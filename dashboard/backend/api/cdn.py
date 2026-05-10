import os
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from services.rbac import require_admin, require_viewer_or_above

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
        "hit": 0,
        "miss": 0,
        "bypass": 0,
        "total_requests": 0,
        "status_2xx": 0,
        "status_4xx": 0,
        "status_5xx": 0,
    }

    for region in EDGE_PORTS:
        h = base_hits[region]
        m = base_miss[region]
        b = base_bypass[region]
        total = h + m + b
        mock[region] = {
            "region": region,
            "hit": h,
            "miss": m,
            "bypass": b,
            "expired": int(m * 0.1),
            "stale": int(m * 0.05),
            "total_requests": total,
            "hit_rate_pct": round((h / total) * 100, 2),
            "miss_rate_pct": round((m / total) * 100, 2),
            "status_2xx": int(total * 0.93),
            "status_4xx": int(total * 0.05),
            "status_5xx": int(total * 0.02),
            "avg_response_time_ms": {"SG": 13.1, "JP": 17.3, "TH": 10.4}[region],
            "last_updated": None,
        }
        for key in total_all:
            total_all[key] += mock[region].get(key, 0)

    gt = total_all["total_requests"] or 1
    mock["GLOBAL"] = {
        "region": "GLOBAL",
        **total_all,
        "hit_rate_pct": round((total_all["hit"] / gt) * 100, 2),
        "miss_rate_pct": round((total_all["miss"] / gt) * 100, 2),
        "last_updated": None,
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
    g = raw.get("GLOBAL", {})
    return {
        "nodes": nodes,
        "global": g,
        "summary": {
            "total_edge_nodes": len(EDGE_PORTS),
            "global_hit_rate_pct": g.get("hit_rate_pct", 0),
            "global_miss_rate_pct": g.get("miss_rate_pct", 0),
            "total_requests": g.get("total_requests", 0),
        },
    }


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
                health_data = {"health": r.text.strip()} if online else {}
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

    online_count = sum(1 for n in results if n["status"] == "online")
    return {
        "nodes": results,
        "online_count": online_count,
        "total_count": len(results),
    }


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
