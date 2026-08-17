from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from services.ml_rule_service import MLRuleService
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/ml-rules", tags=["ml-rules"])
rule_service = MLRuleService()

class RuleRejectRequest(BaseModel):
    reason: Optional[str] = ""

@router.get("/")
async def list_ml_rules(status: Optional[str] = None, current_user: dict = Depends(require_viewer_or_above)):
    try:
        rules = rule_service.list_rules(status)
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{rule_id}")
async def get_ml_rule(rule_id: str, current_user: dict = Depends(require_viewer_or_above)):
    rule = rule_service.get_rule_detail(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.post("/{rule_id}/approve")
async def approve_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    try:
        rule = rule_service.approve_rule(rule_id, approved_by=current_user.get("username", "admin"))
        return {"message": "Rule approved and deployed", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{rule_id}/reject")
async def reject_ml_rule(rule_id: str, req: RuleRejectRequest, current_user: dict = Depends(require_admin)):
    try:
        rule = rule_service.reject_rule(rule_id, rejected_by=current_user.get("username", "admin"), reason=req.reason)
        return {"message": "Rule rejected", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{rule_id}")
async def delete_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    success = rule_service.delete_rule(rule_id)
    if success:
        return {"message": "Rule deleted"}
    raise HTTPException(status_code=404, detail="Rule not found")
