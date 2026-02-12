from fastapi import APIRouter
from services.rule_manager import RuleManager

router = APIRouter(prefix="/rules", tags=["rules"])

rule_manager = RuleManager()

@router.get("/")
def list_rules():
    return rule_manager.list_rules()