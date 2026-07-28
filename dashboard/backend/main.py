import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# อ่าน allowed origins จาก env (คั่นด้วย comma)
# ตัวอย่าง ALLOWED_ORIGINS=http://localhost:5173,https://yourdomain.com
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000,http://localhost:8000")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

from services.fetch_logs import get_recent_logs
from fastapi.responses import FileResponse
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from api import rules
from api import auth
from api import cdn
from api import origins
from api import domains
from api import limiter as rate_limit_api
from api import analytics
from services.log_forward import log_forward_worker
from services.cdn_log_forward import cdn_log_forward_worker
from services.telegram_listener import alert_worker
from services.dns_verification_worker import dns_verification_worker
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

# [R1 FIX] เพิ่ม Rate Limiter เพื่อป้องกัน brute force
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# [S1 FIX] ห้ามใช้ allow_origins=["*"] ร่วมกับ allow_credentials=True
# เพราะขัด CORS spec และเปิดช่องโหว่ CSRF — ใช้ explicit origins แทน
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

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

# Provide fallback for local dev vs prod
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


# Consolidated system health status monitoring
@app.get("/api/system/status")
async def system_status(current_user: dict = Depends(require_viewer_or_above)):
    import socket
    import httpx
    import shutil
    import os
    import time

    # Check port helper
    def check_port(host: str, port: int, timeout=1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    # 1. Database Health
    db_status = "offline"
    db_detail = "Disconnected"
    try:
        from services.dynamodb_service import DynamoDBService
        db_srv = DynamoDBService()
        db_srv.alerts_table.load()
        db_status = "online"
        db_detail = "Connected to AWS DynamoDB"
    except Exception as e:
        db_detail = str(e)

    # 2. Service checks
    services = {
        "Core WAF Engine (Nginx)": {
            "status": "online" if check_port("localhost", 8080) else "offline",
            "port": 8080,
            "desc": "Primary ingress Nginx proxy with ModSecurity CRS"
        },
        "DVWA Target App": {
            "status": "online" if check_port("localhost", 80) else "offline",
            "port": 80,
            "desc": "Vulnerable test application target"
        },
        "CDN Control API": {
            "status": "online" if check_port("localhost", 8070) else "offline",
            "port": 8070,
            "desc": "Coordinates rules sync and blocklists across nodes"
        },
        "CDN Purge API": {
            "status": "online" if check_port("localhost", 8090) else "offline",
            "port": 8090,
            "desc": "Triggers global CDN cache purges"
        },
        "CDN Stats Service": {
            "status": "online" if check_port("localhost", 9090) else "offline",
            "port": 9090,
            "desc": "Aggregates edge node traffic metrics"
        },
        "GeoDNS Server": {
            "status": "online" if check_port("localhost", 8053) else "offline",
            "port": 8053,
            "desc": "DNS server routing users based on geography"
        }
    }

    # 3. CDN Edge Nodes
    cdn_nodes = []
    async with httpx.AsyncClient(timeout=1.5) as client:
        for region, port in [("SG", 8081), ("JP", 8082), ("TH", 8086)]:
            online = check_port("localhost", port)
            latency = 0
            health_status = {}
            if online:
                try:
                    t0 = time.time()
                    r = await client.get(f"http://localhost:{port}/healthz")
                    latency = int((time.time() - t0) * 1000)
                    if r.status_code == 200:
                        health_status = r.json()
                except Exception:
                    pass

            cdn_nodes.append({
                "region": region,
                "status": "online" if online else "offline",
                "port": port,
                "latency_ms": latency,
                "health": health_status
            })

    # 4. Background Workers Status
    workers = {
        "Alert Worker": {
            "status": "running" if hasattr(app.state, "alert_task") and not app.state.alert_task.done() else "stopped",
            "desc": "Forwards security alerts to Telegram channels"
        },
        "Log Forwarder": {
            "status": "running" if hasattr(app.state, "log_forward_task") and not app.state.log_forward_task.done() else "stopped",
            "desc": "Ingests ModSecurity audit logs into database"
        },
        "CDN Log Forwarder": {
            "status": "running" if hasattr(app.state, "cdn_log_forward_task") and not app.state.cdn_log_forward_task.done() else "stopped",
            "desc": "Syncs regional edge logs with control panel"
        },
        "DNS Verification Worker": {
            "status": "running" if hasattr(app.state, "dns_verification_task") and not app.state.dns_verification_task.done() else "stopped",
            "desc": "Verifies customer domain CNAME/TXT DNS records"
        }
    }

    # 5. Disk Info
    total, used, free = shutil.disk_usage("/")

    return {
        "db": {
            "status": db_status,
            "detail": db_detail
        },
        "services": services,
        "cdn_nodes": cdn_nodes,
        "workers": workers,
        "system": {
            "disk_total_gb": total // (2**30),
            "disk_used_gb": used // (2**30),
            "disk_free_gb": free // (2**30),
            "disk_used_percent": int((used / total) * 100),
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0]
        }
    }



# Logs (protected - viewer+)
@app.get("/api/logs/recent")
async def fetch_recent_logs(
    limit: int = 10,
    current_user: dict = Depends(require_viewer_or_above),
):
    logs = get_recent_logs(limit)
    return {"logs": logs}

# API Routers
app.include_router(auth.router)
app.include_router(rules.router)
app.include_router(alerts.router)  
app.include_router(cdn.router)
app.include_router(origins.router)
app.include_router(domains.router)
app.include_router(rate_limit_api.router)
app.include_router(analytics.router)

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
        db.alerts_table.load()  # ping table
        return {"status": "ok", "dynamodb": "connected"}
    except Exception as e:
        return {"status": "error", "dynamodb": str(e)}

# Startup & Shutdown
@app.on_event("startup")
async def startup_event():
    print("=" * 50)
    print("WAF Dashboard API Starting...")
    print("=" * 50)
    print("Dashboard: http://localhost:8000")
    print("API Docs:  http://localhost:8000/docs")
    print("Auth:      http://localhost:8000/api/auth/")
    print("Rules API: http://localhost:8000/api/rules/")
    print("=" * 50)
    if not hasattr(app.state, "alert_task"):
        app.state.alert_task = asyncio.create_task(alert_worker())
    if not hasattr(app.state, "log_forward_task"):
        app.state.log_forward_task = asyncio.create_task(log_forward_worker())
    if not hasattr(app.state, "cdn_log_forward_task"):
        app.state.cdn_log_forward_task = asyncio.create_task(cdn_log_forward_worker())
    if not hasattr(app.state, "dns_verification_task"):
        app.state.dns_verification_task = asyncio.create_task(dns_verification_worker())
    # [S4 FIX] cleanup expired Telegram pairing codes จาก _pending ทุก 60 วินาที
    if not hasattr(app.state, "cleanup_pending_task"):
        from api.alerts import _cleanup_expired_codes
        app.state.cleanup_pending_task = asyncio.create_task(_cleanup_expired_codes())


@app.on_event("shutdown")
async def shutdown_event():
    print("WAF Dashboard API Shutting down...")

# SPA Catch-all route for React Router (MUST be at the bottom)
@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="API route not found")
    
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
