import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

from services.fetch_logs import get_recent_logs
from fastapi.responses import FileResponse
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from api import rules
from api import auth
from api import cdn
from services.log_forward import log_forward_worker
from services.cdn_log_forward import cdn_log_forward_worker
from services.telegram_listener import alert_worker
from services.rbac import require_viewer_or_above
from api import alerts          

app = FastAPI(
    title="WAF Security Dashboard",
    description="Dashboard for WAF management and monitoring",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
