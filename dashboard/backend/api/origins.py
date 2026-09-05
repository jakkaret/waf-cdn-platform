from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional
from services.rbac import get_current_user, verify_origin_ownership
import services.origin_service as origin_service

router = APIRouter(prefix="/api/origins", tags=["Origins"])

class OriginCreate(BaseModel):
    label: str
    ip: str
    port: int = Field(ge=1, le=65535)

class OriginUpdate(BaseModel):
    label: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)

@router.post("")
async def create_origin(origin: OriginCreate, current_user: dict = Depends(get_current_user)):
    try:
        data = origin_service.create_origin(
            admin_user_id=current_user.get("user_id"),
            label=origin.label,
            ip=origin.ip,
            port=origin.port
        )
        o = dict(data)
        o["origin_id"] = o.get("id")
        o["health"] = o.get("health", "unknown")
        return o
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/quota")
async def get_quota(current_user: dict = Depends(get_current_user)):
    """Return quota usage for the current user (origins used / max)."""
    info = origin_service.get_quota_info(current_user.get("user_id"))
    return info

@router.get("")
async def list_origins(current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")
    
    # Auto-sync active tunnels as origins for seamless zero-touch experience
    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    
    origins_list = origin_service.get_origins_for_user(user_id)
    formatted_origins = []
    for origin in origins_list:
        o = dict(origin)
        o["origin_id"] = o.get("id")
        o["health"] = o.get("health", "unknown")
        formatted_origins.append(o)
    # Sort by created_at descending (newest first)
    formatted_origins.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"origins": formatted_origins}

@router.get("/{origin_id}")
async def get_origin(origin: dict = Depends(verify_origin_ownership)):
    o = dict(origin)
    o["origin_id"] = o.get("id")
    o["health"] = o.get("health", "unknown")
    return o

@router.put("/{origin_id}")
async def update_origin(origin_id: str, payload: OriginUpdate, origin: dict = Depends(verify_origin_ownership)):
    try:
        success = origin_service.update_origin(
            origin_id=origin_id,
            label=payload.label,
            ip=payload.ip,
            port=payload.port
        )
        if success:
            return {"status": "success", "message": "Origin updated successfully"}
        raise HTTPException(status_code=500, detail="Failed to update origin")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{origin_id}")
async def delete_origin(origin_id: str, origin: dict = Depends(verify_origin_ownership)):
    success = origin_service.delete_origin(origin_id)
    if success:
        return {"status": "success", "message": "Origin deleted successfully"}
    raise HTTPException(status_code=500, detail="Failed to delete origin")

@router.post("/{origin_id}/restore")
async def restore_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_ownership(origin_id, current_user)
    quota = origin_service.get_quota_info(current_user.get("user_id"))
    if quota["origins"]["at_limit"]:
        raise HTTPException(status_code=400, detail="Cannot restore. Active origin quota exceeded.")
    success = origin_service.restore_origin(origin_id)
    if success:
        return {"status": "success", "message": "Origin restored successfully"}
    raise HTTPException(status_code=500, detail="Failed to restore origin")
