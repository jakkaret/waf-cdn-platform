"""Per-origin WAF rules: an origin's own Admins write them, its Viewers can
read them, nobody else can see them. See services/tenant_rules.py for how a
rule is scoped to only that origin's Host at the WAF level."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.rules import rule_manager  # shared singleton -- same rules_dir/nginx gate as legacy + managed rules
from services.rbac import get_current_user, verify_origin_access, verify_origin_edit_access
from services.tenant_rules import MAX_RULES_PER_ORIGIN, TenantRuleError, TenantRuleService, VARIABLES, OPERATORS, ACTIONS, SEVERITIES, TEMPLATES

router = APIRouter(prefix="/api/origins/{origin_id}/waf-rules", tags=["tenant-rules"])
_service = TenantRuleService(rule_manager)


class TenantRuleIn(BaseModel):
    variable: str
    operator: str
    message: str
    action: Optional[str] = "BLOCK"
    severity: Optional[str] = "HIGH"
    deception_template: Optional[str] = "auto"
    enabled: Optional[bool] = True


@router.get("/options")
async def get_options(current_user: dict = Depends(get_current_user)):
    """Fixed choices the rule builder UI renders -- nothing here is free text
    except the operator's value and the message."""
    return {
        "variables": VARIABLES,
        "operators": sorted(OPERATORS),
        "actions": sorted(ACTIONS),
        "severities": sorted(SEVERITIES),
        "deception_templates": sorted(TEMPLATES),
        "max_rules_per_origin": MAX_RULES_PER_ORIGIN,
    }


@router.get("/")
async def list_rules(origin: dict = Depends(verify_origin_access)):
    return {"rules": _service.list([origin["id"]])}


@router.post("/")
async def create_rule(rule: TenantRuleIn, origin: dict = Depends(verify_origin_edit_access), current_user: dict = Depends(get_current_user)):
    try:
        return _service.create(origin["id"], rule.model_dump(), current_user)
    except TenantRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to apply rule: {e}")


@router.put("/{rule_id}")
async def update_rule(rule_id: int, rule: TenantRuleIn, origin: dict = Depends(verify_origin_edit_access), current_user: dict = Depends(get_current_user)):
    try:
        return _service.update(origin["id"], rule_id, rule.model_dump(), current_user)
    except KeyError:
        raise HTTPException(status_code=404, detail="rule not found")
    except TenantRuleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to apply rule: {e}")


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, origin: dict = Depends(verify_origin_edit_access)):
    try:
        _service.delete(origin["id"], rule_id)
        return {"message": "deleted"}
    except KeyError:
        raise HTTPException(status_code=404, detail="rule not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to apply deletion: {e}")
