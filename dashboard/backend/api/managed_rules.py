"""Central managed ruleset: one versioned set of rules published from
modsecurity/managed-rules/ (see services/managed_ruleset.py), scoped per
origin via managed-00-hostmap.conf. No one can edit it through the API -- an
origin's Admin can only choose auto/manual and, in manual mode, which
published version to run, or ask for a check-now (platform admin)."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import services.managed_ruleset as mr
from api.rules import rule_manager as _rule_manager  # shared singleton -- same rules_dir/nginx gate as legacy + tenant rules
from services.dynamodb_service import DynamoDBService
from services.rbac import require_admin, verify_origin_access, verify_origin_edit_access

router = APIRouter(prefix="/api/managed-rules", tags=["managed-rules"])
_db = DynamoDBService()


class ModeUpdate(BaseModel):
    mode: str  # "auto" | "manual"
    version: Optional[int] = None  # required to switch into manual, or to change the pin while manual


@router.get("/origins/{origin_id}/status")
async def get_status(origin: dict = Depends(verify_origin_access)):
    return mr.status_for_origin(origin)


@router.put("/origins/{origin_id}/mode")
async def set_mode(origin_id: str, body: ModeUpdate, origin: dict = Depends(verify_origin_edit_access)):
    mode = body.mode.strip().lower()
    if mode not in (mr.MODE_AUTO, mr.MODE_MANUAL):
        raise HTTPException(status_code=400, detail="mode must be 'auto' or 'manual'")
    catalog = mr.load_catalog()
    latest = mr.latest_version(catalog)
    update = {"managed_ruleset_mode": mode}
    if mode == mr.MODE_MANUAL:
        version = body.version if body.version is not None else latest
        if not 0 <= version <= latest:
            raise HTTPException(status_code=400, detail=f"version must be between 0 and {latest}")
        update["managed_ruleset_version"] = version
    if not _db.update_origin(origin_id, update):
        raise HTTPException(status_code=500, detail="failed to save origin setting")
    try:
        mr.apply(_rule_manager, _db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"setting saved but the WAF reload failed: {e}")
    return mr.status_for_origin(_db.get_origin_by_id(origin_id), catalog)


@router.post("/origins/{origin_id}/update")
async def update_to_latest(origin_id: str, origin: dict = Depends(verify_origin_edit_access)):
    """Manual mode: the origin's Admin presses Update to jump to the latest
    published version, without switching the origin to auto."""
    catalog = mr.load_catalog()
    latest = mr.latest_version(catalog)
    if not _db.update_origin(origin_id, {"managed_ruleset_version": latest}):
        raise HTTPException(status_code=500, detail="failed to save origin setting")
    try:
        mr.apply(_rule_manager, _db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"version saved but the WAF reload failed: {e}")
    return mr.status_for_origin(_db.get_origin_by_id(origin_id), catalog)


# ----------------------------------------------------------- platform admin

@router.get("/catalog")
async def get_catalog(current_user: dict = Depends(require_admin)):
    """Every published version and rule -- platform admin only (spans every
    origin, unlike the per-origin status endpoint above)."""
    return mr.load_catalog()


@router.post("/publish")
async def publish_now(current_user: dict = Depends(require_admin)):
    """Check modsecurity/managed-rules/ for a change and publish a new
    version immediately, instead of waiting for the update worker's next
    tick. No-op (returns published: false) when the source hasn't changed."""
    try:
        entry = mr.publish()
    except mr.ManagedRulesetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if entry is None:
        return {"published": False}
    try:
        mr.apply(_rule_manager, _db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"published v{entry['version']} but the WAF reload failed: {e}")
    return {"published": True, "version": entry}
