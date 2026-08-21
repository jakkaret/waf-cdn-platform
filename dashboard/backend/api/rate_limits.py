from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from services.rate_limit_service import RateLimitService
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/rate-limits", tags=["rate-limits"])
service = RateLimitService()


class RateRuleCreate(BaseModel):
    name: str = Field(..., description="Descriptive name of the rate limit policy")
    path_pattern: str = Field(..., description="Target URI pattern (e.g. /api/auth/*, /login, *)")
    method: str = Field("ALL", description="HTTP method: ALL, GET, POST, etc.")
    limit_count: int = Field(..., ge=1, description="Max allowed requests within time window")
    window_seconds: int = Field(..., ge=1, description="Sliding window duration in seconds")
    burst: int = Field(0, ge=0, description="Allowed burst count above the limit")
    action: str = Field("429", description="Action to take: '429' or 'temp_ban'")


class RateRuleUpdate(BaseModel):
    name: Optional[str] = None
    path_pattern: Optional[str] = None
    method: Optional[str] = None
    limit_count: Optional[int] = None
    window_seconds: Optional[int] = None
    burst: Optional[int] = None
    action: Optional[str] = None
    enabled: Optional[int] = None


class ResetClientRequest(BaseModel):
    ip: str


@router.get("/rules")
async def list_rate_rules(
    current_user: dict = Depends(require_viewer_or_above),
):
    try:
        rules = service.list_rules()
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules")
async def create_rate_rule(
    payload: RateRuleCreate,
    current_user: dict = Depends(require_admin),
):
    try:
        created = service.add_rule(
            name=payload.name,
            path_pattern=payload.path_pattern,
            limit_count=payload.limit_count,
            window_seconds=payload.window_seconds,
            method=payload.method,
            burst=payload.burst,
            action=payload.action
        )
        return {"status": "success", "rule": created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/rules/{rule_id}")
async def update_rate_rule(
    rule_id: str,
    payload: RateRuleUpdate,
    current_user: dict = Depends(require_admin),
):
    try:
        data = {k: v for k, v in payload.dict().items() if v is not None}
        updated = service.update_rule(rule_id, data)
        if updated:
            return {"status": "success", "rule": updated}
        raise HTTPException(status_code=404, detail="Rate rule not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rules/{rule_id}")
async def delete_rate_rule(
    rule_id: str,
    current_user: dict = Depends(require_admin),
):
    try:
        deleted = service.delete_rule(rule_id)
        if deleted:
            return {"status": "success", "message": f"Rule {rule_id} deleted"}
        raise HTTPException(status_code=404, detail="Rate rule not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/throttled")
async def get_throttled_clients(
    current_user: dict = Depends(require_viewer_or_above),
):
    try:
        clients = service.get_throttled_clients()
        return {"throttled_clients": clients}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset-client")
async def reset_client(
    payload: ResetClientRequest,
    current_user: dict = Depends(require_admin),
):
    try:
        success = service.reset_client_limit(payload.ip)
        if success:
            return {"status": "success", "message": f"Rate limit for {payload.ip} reset"}
        return {"status": "info", "message": f"No active rate limit bucket found for {payload.ip}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
