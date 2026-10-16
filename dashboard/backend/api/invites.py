from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services import audit_log, invite_service
from services.rbac import get_current_user
from services.txn import atomic

router = APIRouter(prefix="/api/invites", tags=["Invites"])


class AcceptInvite(BaseModel):
    token: str


@router.post("/accept")
async def accept_invite(body: AcceptInvite, current_user: dict = Depends(get_current_user)):
    """Grant the invited role to the signed-in user who holds the emailed link
    (N9/H64). Unknown, expired and already used links all get the same 404."""
    with atomic():
        result = invite_service.accept_invite(body.token, current_user["user_id"])
        if not result:
            raise HTTPException(status_code=404, detail="This invitation link is invalid or has expired")
        origin_id, role = result
        audit_log.write_audit_event(
            scope_id=origin_id,
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action=f"{role}.grant",
            summary=f"รับคำเชิญเป็น {role}: {current_user.get('email', '')}",
            details={"user_id": current_user.get("user_id"), "via": "invite"},
        )
    from services.tenant_service import invalidate_tenant_cache
    invalidate_tenant_cache(current_user["user_id"])
    return {"status": "accepted", "origin_id": origin_id, "role": role}
