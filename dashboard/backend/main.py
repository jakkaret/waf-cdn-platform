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
from fastapi.responses import FileResponse
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
from api import ml, ml_rules, analytics, origins, domains, ip_rules, rate_limits, settings, ai_summary, tunnels, copilot
app.include_router(ml.router)
app.include_router(ml_rules.router)
app.include_router(analytics.router)
app.include_router(origins.router)
app.include_router(domains.router)
app.include_router(ip_rules.router)
app.include_router(rate_limits.router)
app.include_router(settings.router)
app.include_router(ai_summary.router)
app.include_router(tunnels.router)
app.include_router(copilot.router)

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
        reload=True,
        log_level="info"
    )
