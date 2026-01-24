from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.rule_manager import RuleManager

router = APIRouter(prefix="/api/rules", tags=["rules"])
rule_manager = RuleManager()

class RuleCreate(BaseModel):
    id: str
    variable: str
    operator: str
    severity: str
    message: str

@router.get("/")
async def get_rules():
    """ดึงรายการ rules ทั้งหมด"""
    try:
        rules = rule_manager.list_rules()
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/")
async def create_rule(rule: RuleCreate):
    """สร้าง rule ใหม่"""
    try:
        success = rule_manager.add_rule(rule.dict())
        if success:
            return {"message": "Rule created", "rule_id": rule.id}
        raise HTTPException(status_code=500, detail="Failed to create rule")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    """ลบ rule"""
    try:
        success = rule_manager.delete_rule(rule_id)
        if success:
            return {"message": "Rule deleted"}
        raise HTTPException(status_code=404, detail="Rule not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
