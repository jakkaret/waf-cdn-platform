"""Per-origin OTP / CAPTCHA shield activity. An origin's Admins and Viewers
read their own origin's events only (verify_origin_access)."""
from fastapi import APIRouter, Depends, HTTPException, Query

from services.clickhouse_service import ClickHouseService
from services.rbac import verify_origin_access
from services.shield_events import summary_for_origin

router = APIRouter(prefix="/api/origins/{origin_id}/shield-events", tags=["shield-events"])
ch = ClickHouseService()


@router.get("")
async def get_shield_events(
    hours: int = Query(24, ge=1, le=24 * 90),
    limit: int = Query(100, ge=1, le=500),
    origin: dict = Depends(verify_origin_access),
):
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    return summary_for_origin(ch, origin["id"], hours=hours, limit=limit)
