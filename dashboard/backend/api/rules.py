from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from services.rule_manager import RuleManager
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/rules", tags=["rules"])
rule_manager = RuleManager()


class RuleCreate(BaseModel):
    id: str
    variable: str
    operator: str
    severity: str
    message: str


class RuleSchema(BaseModel):
    variable: str
    operator: str
    severity: str
    message: str


@router.get("/")
async def get_rules(current_user: dict = Depends(require_viewer_or_above)):
    try:
        rules = rule_manager.list_rules()
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def create_rule(rule: RuleCreate, current_user: dict = Depends(require_admin)):
    try:
        success = rule_manager.add_rule(rule.dict())
        if success:
            return {"message": "Rule created", "rule_id": rule.id}
        raise HTTPException(status_code=500, detail="Failed to create rule")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    try:
        success = rule_manager.delete_rule(rule_id)
        if success:
            return {"message": "Rule deleted"}
        raise HTTPException(status_code=404, detail="Rule not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{rule_id}")
async def update_rule(rule_id: str, rule: RuleSchema, current_user: dict = Depends(require_admin)):
    try:
        rule_manager.update_rule(rule_id, rule.dict())
        return {"status": "updated", "rule_id": rule_id}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
