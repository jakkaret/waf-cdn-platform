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
        return data
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("")
async def list_origins(current_user: dict = Depends(get_current_user)):
    return origin_service.get_origins_for_user(current_user.get("user_id"))

@router.get("/{origin_id}")
async def get_origin(origin: dict = Depends(verify_origin_ownership)):
    return origin

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
