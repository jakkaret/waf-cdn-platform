import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Literal, Optional
from services.settings_service import SettingsService, mask_settings
from services.rbac import require_viewer_or_above, require_admin
from services import audit_log
from services.txn import atomic

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
    # P4.5 (H20): typed and bounded -- a typo in waf_mode used to switch the
    # WAF to DetectionOnly silently; now it is a 422.
    model_config = {"extra": "forbid"}
    waf_mode: Optional[Literal["blocking", "detection_only"]] = None
    paranoia_level: Optional[int] = Field(None, ge=1, le=4)
    inbound_anomaly_threshold: Optional[int] = Field(None, ge=1, le=1000)
    outbound_anomaly_threshold: Optional[int] = Field(None, ge=1, le=1000)
    auto_purge_edge_cache: Optional[bool] = None
    real_ip_header: Optional[Literal["X-Forwarded-For", "X-Real-IP"]] = None
    telegram_notifications: Optional[bool] = None
    telegram_bot_token: Optional[str] = Field(None, max_length=200)
    telegram_chat_id: Optional[str] = Field(None, pattern=r"^-?\d{1,20}$|^$")
    edge_sync_interval_seconds: Optional[int] = Field(None, ge=1, le=3600)


@router.get("/")
async def get_settings(
    current_user: dict = Depends(require_viewer_or_above),
):
    try:
        settings = service.get_settings()
        return {"settings": mask_settings(settings, is_admin=current_user.get("role") == "admin")}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to load settings")


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
            try:
                # Settings live in a file, so they cannot share a database
                # transaction: the file is written first, then the audit
                # event in its own short transaction. If the audit cannot be
                # written (PostgreSQL audit is fail-closed), the previous
                # values are put back so no change goes unrecorded.
                with atomic():
                    audit_log.write_audit_event(
                        scope_id=AUDIT_SCOPE_GLOBAL,
                        actor_user_id=current_user.get("user_id"),
                        actor_username=current_user.get("username", ""),
                        action="settings.update",
                        summary=f"แก้ system settings: {', '.join(changed.keys())}",
                        details=changed,
                    )
            except Exception as audit_exc:
                try:
                    service.update_settings({k: before.get(k) for k in changed})
                except Exception as undo_exc:
                    logging.getLogger(__name__).critical(
                        "settings changed without an audit event and could not be reverted: "
                        "audit=%s revert=%s", audit_exc, undo_exc)
                raise HTTPException(status_code=500, detail="Settings not saved: the audit log is unavailable")

        return {"status": "success", "settings": mask_settings(updated)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
