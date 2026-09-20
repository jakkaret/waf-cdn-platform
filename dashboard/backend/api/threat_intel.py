from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from services.rbac import get_current_user
from services.auth_service import AuthService
from services import threat_intel

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intel"])
auth_service = AuthService()


class OptInRequest(BaseModel):
    enabled: bool


@router.patch("/opt-in")
async def set_opt_in(payload: OptInRequest, current_user: dict = Depends(get_current_user)):
    """Per-user, not global (unlike api/settings.py's system-wide config) --
    threat_intel.py reads this flag fresh on every write and read, so
    turning it off here stops sharing starting with the very next attack,
    not after some cache TTL."""
    auth_service.set_threat_intel_opt_in(current_user["user_id"], payload.enabled)
    return {"share_threat_intel": payload.enabled}


@router.get("/trending")
async def get_trending(current_user: dict = Depends(get_current_user)):
    """Reciprocity gate lives in services/threat_intel.py itself: only a
    tenant who has opted in may read the community feed."""
    try:
        patterns = threat_intel.get_trending_patterns(current_user["user_id"])
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return {"patterns": patterns}
