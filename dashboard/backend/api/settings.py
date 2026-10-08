from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from services.settings_service import SettingsService, mask_settings
from services.rbac import require_viewer_or_above, require_admin
from services import audit_log

router = APIRouter(prefix="/api/settings", tags=["settings"])
service = SettingsService()

# System settings are global (not tied to one origin), so audit events for
# them use this fixed scope_id rather than an origin_id -- matches
# services/audit_log.py's documented convention.
AUDIT_SCOPE_GLOBAL = "global"
# Never write a real secret value into a persistent store (standing rule,
# this session) -- a changed telegram_bot_token is recorded as "changed",
# never its old/new value.
_SECRET_FIELDS = {"telegram_bot_token"}


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
        return {"settings": mask_settings(settings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def update_settings(
    payload: SettingsUpdate,
    current_user: dict = Depends(require_admin),
):
    try:
        data = {k: v for k, v in payload.dict().items() if v is not None}
        before = service.get_settings()
        updated = service.update_settings(data)

        changed = {}
        for field, new_value in data.items():
            old_value = before.get(field)
            if old_value == new_value:
                continue
            if field in _SECRET_FIELDS:
                changed[field] = {"old": "(changed)", "new": "(changed)"}
            else:
                changed[field] = {"old": old_value, "new": new_value}

        if changed:
            audit_log.write_audit_event(
                scope_id=AUDIT_SCOPE_GLOBAL,
                actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""),
                action="settings.update",
                summary=f"แก้ system settings: {', '.join(changed.keys())}",
                details=changed,
            )

        return {"status": "success", "settings": mask_settings(updated)}
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
