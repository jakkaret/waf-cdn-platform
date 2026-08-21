from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from services.settings_service import SettingsService
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/settings", tags=["settings"])
service = SettingsService()


class SettingsUpdate(BaseModel):
    waf_mode: Optional[str] = None
    paranoia_level: Optional[int] = None
    inbound_anomaly_threshold: Optional[int] = None
    outbound_anomaly_threshold: Optional[int] = None
    auto_purge_edge_cache: Optional[bool] = None
    real_ip_header: Optional[str] = None
    telegram_notifications: Optional[bool] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    edge_sync_interval_seconds: Optional[int] = None


class TestNotificationRequest(BaseModel):
    channel: str = "telegram"


@router.get("/")
async def get_settings(
    current_user: dict = Depends(require_viewer_or_above),
):
    try:
        settings = service.get_settings()
        return {"settings": settings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def update_settings(
    payload: SettingsUpdate,
    current_user: dict = Depends(require_admin),
):
    try:
        data = {k: v for k, v in payload.dict().items() if v is not None}
        updated = service.update_settings(data)
        return {"status": "success", "settings": updated}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-notification")
async def send_test_alert(
    payload: TestNotificationRequest,
    current_user: dict = Depends(require_admin),
):
    try:
        result = await service.send_test_notification(payload.channel)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
