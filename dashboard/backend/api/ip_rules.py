from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from services.ip_rule_service import IPRuleService
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/ip-rules", tags=["ip-rules"])
service = IPRuleService()


class IPRuleCreate(BaseModel):
    ip: str = Field(..., description="IP address or CIDR notation (e.g. 192.168.1.1 or 10.0.0.0/24)")
    rule_type: str = Field("block", description="'block' or 'allow'")
    reason: str = Field("Manual entry", description="Reason for the rule")
    duration_seconds: Optional[int] = Field(None, description="TTL in seconds. None/0 means permanent")
    source: str = Field("manual", description="Origin of rule ('manual', 'ml_analyst', 'rate_limit')")


class BulkDeleteRequest(BaseModel):
    ips: List[str]


@router.get("/")
async def get_ip_rules(
    rule_type: Optional[str] = Query("all", description="'all', 'block', or 'allow'"),
    search: Optional[str] = Query(None, description="Search term for IP or reason"),
    current_user: dict = Depends(require_viewer_or_above),
):
    try:
        rules = service.list_rules(rule_type=rule_type, search=search)
        stats = service.get_stats()
        return {
            "rules": rules,
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def add_ip_rule(
    payload: IPRuleCreate,
    current_user: dict = Depends(require_admin),
):
    try:
        username = current_user.get("username", "admin")
        result = service.add_rule(
            ip=payload.ip,
            rule_type=payload.rule_type,
            reason=payload.reason,
            added_by=username,
            duration_seconds=payload.duration_seconds,
            source=payload.source
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{ip:path}")
async def delete_ip_rule(
    ip: str,
    current_user: dict = Depends(require_admin),
):
    try:
        deleted = service.delete_rule(ip)
        if deleted:
            return {"status": "success", "message": f"Rule for IP {ip} removed"}
        raise HTTPException(status_code=404, detail="IP rule not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk-delete")
async def bulk_delete_rules(
    payload: BulkDeleteRequest,
    current_user: dict = Depends(require_admin),
):
    try:
        count = service.bulk_delete(payload.ips)
        return {"status": "success", "deleted_count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
