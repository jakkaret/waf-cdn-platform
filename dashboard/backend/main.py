#WAF Dashboard 
import os
import asyncio
from routers.rules import router as rules_router
from fastapi.responses import FileResponse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from services.log_forward import log_forward_worker
from services.telegram_listener import alert_worker

app = FastAPI(
    title="WAF Security Dashboard",
    description="Dashboard สำหรับจัดการและติดตามระบบ WAF",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#Static Files
frontend_path = os.path.join(os.path.dirname(__file__), "../frontend")
app.mount("/assets", StaticFiles(directory=os.path.join(frontend_path, "assets")), name="assets")

#API Routes
@app.get("/")
async def root():
    return FileResponse(os.path.join(frontend_path, "index.html"))

# @app.get("/api/health")
# async def health_check():
#     return {
#         "api": "ok",
#         "waf_container": "waf-nginx",
#         "rules_loaded": True
#     }


@app.get("/api/system/info")
async def system_info():
    return {
        "waf_status": "online",
        "dashboard_version": "1.0.0",
        "backend": "FastAPI",
        "frontend": "HTML/CSS/JS"
    }

#Include API Routers 
app.include_router(rules_router)

#HTML Routes
@app.get("/index.html")
async def serve_index():
    return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/logs.html")
async def serve_logs():
    return FileResponse(os.path.join(frontend_path, "logs.html"))

@app.get("/rules.html")
async def serve_rules():
    return FileResponse(os.path.join(frontend_path, "rules.html"))

@app.get("/alerts.html")
async def serve_alerts():
    return FileResponse(os.path.join(frontend_path, "alerts.html"))

#Error Handlers
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
    print("🔥 Internal Error:", exc)
    return JSONResponse(
        status_code=500,
        content={"error": str(exc)}
    )


#Startup & Shutdown
@app.on_event("startup")
async def startup_event():
    print("=" * 50)
    print("🛡️  WAF Dashboard API Starting...")
    print("=" * 50)
    print("📊 Dashboard: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    print("🔧 Health: http://localhost:8000/api/health")
    print("⚙️  Rules API: http://localhost:8000/api/rules/")
    print("=" * 50)
    # 🔥 start background task
    if not hasattr(app.state, "alert_task"):
        app.state.alert_task = asyncio.create_task(alert_worker())
    if not hasattr(app.state, "log_forward_task"):
        app.state.log_forward_task = asyncio.create_task(log_forward_worker())

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 WAF Dashboard API Shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
