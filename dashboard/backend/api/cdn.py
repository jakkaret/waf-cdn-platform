"""
dashboard/backend/api/cdn.py
Phase 1 – CDN Stats API endpoint

เพิ่ม router นี้เข้า main.py:
    from api import cdn
    app.include_router(cdn.router)

Endpoints:
    GET /api/cdn/stats        → cache hit/miss ทุก region
    GET /api/cdn/stats/{region} → เฉพาะ region
    GET /api/cdn/nodes        → สถานะ node ทุกตัว
"""

import httpx
from fastapi import APIRouter, HTTPException, Depends
from services.rbac import require_viewer_or_above

router = APIRouter(prefix="/api/cdn", tags=["cdn"])

# ── Config ─────────────────────────────────────────────────
CDN_STATS_URL = "http://cdn-stats:9090/metrics"

# Region metadata (สำหรับ dashboard display)
REGIONS_META = {
    "SG": {"name": "Singapore",   "flag": "🇸🇬", "lat": 1.3521,  "lng": 103.8198},
    "JP": {"name": "Japan",        "flag": "🇯🇵", "lat": 35.6762, "lng": 139.6503},
    "US": {"name": "United States","flag": "🇺🇸", "lat": 37.0902, "lng": -95.7129},
    "DE": {"name": "Germany",      "flag": "🇩🇪", "lat": 51.1657, "lng": 10.4515},
    "CH": {"name": "Switzerland",  "flag": "🇨🇭", "lat": 46.8182, "lng": 8.2275},
}

# Port mapping ของแต่ละ edge (สำหรับ health check)
EDGE_PORTS = {
    "SG": 8081,
    "JP": 8082,
    "US": 8083,
    "DE": 8084,
    "CH": 8085,
}


async def _fetch_stats() -> dict:
    """ดึง stats จาก cdn-stats collector"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(CDN_STATS_URL)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        # fallback: คืน mock data ถ้า collector ยังไม่ได้รัน
        return _mock_stats()


def _mock_stats() -> dict:
    """Mock data ใช้ระหว่าง dev / ถ้า collector offline"""
    mock = {}
    base_hits  = {"SG": 420, "JP": 318, "US": 512, "DE": 275, "CH": 189}
    base_miss  = {"SG": 82,  "JP": 64,  "US": 98,  "DE": 55,  "CH": 41}
    base_bypass= {"SG": 38,  "JP": 29,  "US": 45,  "DE": 22,  "CH": 16}

    total_all = {"hit": 0, "miss": 0, "bypass": 0, "total_requests": 0,
                 "status_2xx": 0, "status_4xx": 0, "status_5xx": 0}

    for region in ["SG", "JP", "US", "DE", "CH"]:
        h = base_hits[region]
        m = base_miss[region]
        b = base_bypass[region]
        total = h + m + b

        mock[region] = {
            "region": region,
            "hit": h, "miss": m, "bypass": b,
            "expired": int(m * 0.1), "stale": int(m * 0.05),
            "total_requests": total,
            "hit_rate_pct": round(h / total * 100, 2),
            "miss_rate_pct": round(m / total * 100, 2),
            "status_2xx": int(total * 0.92),
            "status_4xx": int(total * 0.06),
            "status_5xx": int(total * 0.02),
            "avg_response_time_ms": {"SG": 12.4, "JP": 18.7, "US": 9.2,
                                     "DE": 22.1, "CH": 20.5}[region],
            "last_updated": None,
        }

        for k in total_all:
            total_all[k] += mock[region].get(k, 0)

    gt = total_all["total_requests"] or 1
    mock["GLOBAL"] = {
        "region": "GLOBAL",
        **total_all,
        "hit_rate_pct": round(total_all["hit"] / gt * 100, 2),
        "miss_rate_pct": round(total_all["miss"] / gt * 100, 2),
        "last_updated": None,
    }
    return mock


def _enrich(stats: dict) -> list:
    """แนบ metadata (flag, name, lat/lng) เข้าไปกับ stats"""
    result = []
    for region, data in stats.items():
        if region == "GLOBAL":
            continue
        meta = REGIONS_META.get(region, {})
        result.append({
            **data,
            **meta,
            "port": EDGE_PORTS.get(region),
        })
    return result


# ── Endpoints ────────────────────────────────────────────────

@router.get("/stats")
async def cdn_stats(current_user: dict = Depends(require_viewer_or_above)):
    """
    ดึง cache hit/miss stats ของทุก edge node
    
    Response:
        nodes   → list ของ stats แต่ละ region
        global  → รวมทุก region
        summary → hit_rate เฉลี่ยทั่วโลก
    """
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
        }
    }


@router.get("/stats/{region}")
async def cdn_stats_region(
    region: str,
    current_user: dict = Depends(require_viewer_or_above),
):
    """ดึง stats ของ region ที่ระบุ (SG/JP/US/DE/CH)"""
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
    """
    ตรวจสอบสถานะ (online/offline) ของทุก edge node
    เรียก /healthz endpoint ของแต่ละ node
    """
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

            results.append({
                "region": region,
                "name":   meta.get("name", region),
                "flag":   meta.get("flag", "🌐"),
                "lat":    meta.get("lat"),
                "lng":    meta.get("lng"),
                "port":   port,
                "status": "online" if online else "offline",
                **health_data,
            })

    online_count = sum(1 for n in results if n["status"] == "online")
    return {
        "nodes": results,
        "online_count": online_count,
        "total_count": len(results),
    }
