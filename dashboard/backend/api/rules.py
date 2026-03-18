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

class RuleSchema(BaseModel):
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

@router.put("/{rule_id}")
async def update_rule(rule_id: str, rule: RuleSchema):
    """อัพเดต rule ที่มีอยู่"""
    try:
        print(f"Updating rule: {rule_id}")
        print(f"   Data: {rule.dict()}")
        
        rule_manager.update_rule(rule_id, rule.dict())
        
        print(f"Rule {rule_id} updated successfully")
        return {"status": "updated", "rule_id": rule_id}

    except FileNotFoundError as e:
        print(f"Rule not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))

    except ValueError as e:
        print(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))