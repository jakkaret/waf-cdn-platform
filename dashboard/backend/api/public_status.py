from fastapi import APIRouter, Request, Query
from services.rate_limiter import limiter
from services import public_status

router = APIRouter(prefix="/api/status", tags=["Public Status"])


@router.get("/public")
@limiter.limit("30/minute")
async def get_public_status(request: Request):
    """No auth -- this is meant to be reachable by anyone, the same as
    status.cloudflare.com. See services/public_status.py's module docstring
    for the two hard constraints that make that safe here: a whitelisted
    field set (no IP/hostname ever leaves this) and a 30s cache (no
    per-request amplification of the real edge health checks)."""
    return await public_status.get_public_status_snapshot()


@router.get("/public/history")
@limiter.limit("30/minute")
async def get_public_status_history(request: Request, days: int = Query(default=90, ge=1, le=400)):
    return public_status.get_uptime_history(days=days)
