import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# อ่าน allowed origins จาก env (คั่นด้วย comma)
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://178.104.53.123:5173,http://178.104.53.123:3000,http://178.104.53.123:8000,http://178.104.53.123,http://waf-main-dashboard.duckdns.org,https://waf-main-dashboard.duckdns.org")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

from services.fetch_logs import get_recent_logs
from services.clickhouse_service import ClickHouseService
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi import FastAPI, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from api import rules
from api import limiter as limiter_api
from api import logs as logs_api
from api import auth
from api import cdn
from services.log_forward import log_forward_worker
from services.telegram_listener import alert_worker
from services.rbac import require_viewer_or_above
from api import alerts
from services.rate_limiter import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

app = FastAPI(
    title="WAF Security Dashboard",
    description="Dashboard for WAF management and monitoring",
    version="1.0.0"
)

ch = ClickHouseService()

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ==========================================
# 4. STATIC FILES & REACT APP SERVING
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

assets_dir = FRONTEND_DIST / "assets" if FRONTEND_DIST.exists() else BASE_DIR / "frontend" / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


# System status (protected) -- see frontend/src/api/system.ts for the contract
@app.get("/api/system/status")
async def system_status(current_user: dict = Depends(require_viewer_or_above)):
    import os
    import shutil
    import socket

    def _port_open(port: int, host: str = "127.0.0.1") -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((host, port)) == 0

    # (port, description) for the services this control plane depends on.
    SERVICES = {
        "dashboard_api": (8000, "FastAPI control plane"),
        "waf_nginx": (8080, "nginx + ModSecurity CRS"),
        "redis": (6379, "rate-limit and cache store"),
        "clickhouse": (8123, "traffic log warehouse"),
        "frps": (7000, "FRP tunnel server"),
        "control_api": (8070, "WAF control API"),
    }
    services = {
        name: {
            "status": "online" if _port_open(port) else "offline",
            "port": port,
            "desc": desc,
        }
        for name, (port, desc) in SERVICES.items()
    }

    db_status, db_detail = "offline", "unreachable"
    try:
        from services.dynamodb_service import DynamoDBService
        DynamoDBService().domains_table.table_status
        db_status, db_detail = "online", "DynamoDB reachable"
    except Exception as exc:
        db_detail = f"DynamoDB error: {exc}"[:200]

    cdn_nodes = []
    try:
        from api.cdn import cdn_nodes as _cdn_nodes_handler
        raw_nodes = await _cdn_nodes_handler(current_user=current_user)
        for n in (raw_nodes if isinstance(raw_nodes, list) else raw_nodes.get("nodes", [])):
            cdn_nodes.append({
                "region": n.get("region") or n.get("name") or "unknown",
                "status": n.get("status", "offline"),
                "port": n.get("port", 443),
                "latency_ms": n.get("latency_ms", 0),
                "health": n.get("health", {}),
            })
    except Exception as exc:
        print(f"system/status: CDN node lookup failed: {exc}")

    workers = {
        "tunnel_gatekeeper": {
            "status": "running" if services["frps"]["status"] == "online" else "stopped",
            "desc": "FRP webhook gatekeeper (per-domain tunnel authorization)",
        },
        "log_pipeline": {
            "status": "running" if services["clickhouse"]["status"] == "online" else "stopped",
            "desc": "access log ingestion into ClickHouse",
        },
    }

    total, used, free = shutil.disk_usage("/")
    gb = 1024 ** 3
    load1, load5, load15 = os.getloadavg()

    return {
        "db": {"status": db_status, "detail": db_detail},
        "services": services,
        "cdn_nodes": cdn_nodes,
        "workers": workers,
        "system": {
            "disk_total_gb": round(total / gb, 1),
            "disk_used_gb": round(used / gb, 1),
            "disk_free_gb": round(free / gb, 1),
            "disk_used_percent": round(used / total * 100, 1),
            "load_average": [round(load1, 2), round(load5, 2), round(load15, 2)],
        },
    }


# System info (protected)
@app.get("/api/system/info")
async def system_info(current_user: dict = Depends(require_viewer_or_above)):
    return {
        "waf_status": "online",
        "dashboard_version": "1.0.0",
        "backend": "FastAPI",
        "frontend": "HTML/CSS/JS",
        "user": current_user.get("username"),
        "role": current_user.get("role"),
    }




# API Routers
app.include_router(auth.router)
app.include_router(rules.router)
app.include_router(limiter_api.router)
app.include_router(logs_api.router)
app.include_router(alerts.router)
app.include_router(cdn.router)
from api import ml, ml_rules, analytics, origins, domains, ip_rules, rate_limits, settings, ai_summary, tunnels, copilot, threshold_proposals
from api import tunnel as tunnel_api
app.include_router(ml.router)
app.include_router(ml_rules.router)
app.include_router(analytics.router)
app.include_router(origins.router)
app.include_router(domains.router)
app.include_router(domains.origins_domains_router)
app.include_router(ip_rules.router)
app.include_router(rate_limits.router)
app.include_router(settings.router)
app.include_router(ai_summary.router)
app.include_router(tunnels.router)
app.include_router(tunnel_api.router)
app.include_router(copilot.router)
app.include_router(threshold_proposals.router)

# Error Handlers
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Resource not found", "path": str(request.url)}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    print("Internal Error:", exc)
    return JSONResponse(
        status_code=500,
        content={"error": str(exc)}
    )

@app.get("/api/health")
async def health_check():
    try:
        from services.dynamodb_service import DynamoDBService
        db = DynamoDBService()
        db.alerts_table.load()
        ch_status = "connected" if ch.connected else "disconnected"
        return {"status": "ok", "dynamodb": "connected", "clickhouse": ch_status}
    except Exception as e:
        return {"status": "error", "dynamodb": str(e)}

# Startup & Shutdown
@app.on_event("startup")
async def startup_event():
    print("=" * 50)
    print("WAF Dashboard API Starting...")
    print("=" * 50)
    print("Dashboard: http://178.104.53.123:8000")
    print("API Docs:  http://178.104.53.123:8000/docs")
    print("Auth:      http://178.104.53.123:8000/api/auth/")
    print("Rules API: http://178.104.53.123:8000/api/rules/")
    print("=" * 50)
    if not hasattr(app.state, "alert_task"):
        app.state.alert_task = asyncio.create_task(alert_worker())
    if not hasattr(app.state, "log_forward_task"):
        app.state.log_forward_task = asyncio.create_task(log_forward_worker())
    if not hasattr(app.state, "cleanup_pending_task"):
        from api.alerts import _cleanup_expired_codes
        app.state.cleanup_pending_task = asyncio.create_task(_cleanup_expired_codes())


@app.on_event("shutdown")
async def shutdown_event():
    print("WAF Dashboard API Shutting down...")

# Registered ahead of the SPA catch-all below -- Starlette matches routes in
# registration order, so without these two, requests for /robots.txt and
# /llms.txt fell through to serve_react_app() and got index.html back
# (caught by a Lighthouse a11y/SEO audit, 2026-09-08).
@app.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    # This is a private, login-gated admin dashboard -- nothing on it should
    # be indexed.
    return PlainTextResponse("User-agent: *\nDisallow: /\n")

@app.get("/llms.txt", include_in_schema=False)
async def llms_txt():
    return PlainTextResponse(
        "# WAF + CDN Security Dashboard\n\n"
        "> Real-time monitoring and management console for an intelligent "
        "WAF (ModSecurity/CRS + ML anomaly detection) and CDN edge network. "
        "Login-gated -- most content requires an authenticated session.\n\n"
        "- [Project documentation](https://jakkaret.github.io/Docs-for-WAF-project/)\n"
    )

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="API route not found")

    if full_path:
        target_file = FRONTEND_DIST / full_path
        if target_file.is_file():
            return FileResponse(str(target_file))

    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "React app not built yet. Run 'npm run build' in frontend folder."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
