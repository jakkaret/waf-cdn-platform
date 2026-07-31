from fastapi import APIRouter, HTTPException, Depends, Request
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


@router.post("/sync")
async def sync_rules_to_edges(request: Request, current_user: dict = Depends(require_admin)):
    """
    Trigger sync of WAF rules from this API to all CDN edge nodes.
    Runs sync_waf_rules.py as a subprocess, passing the caller's JWT token.
    Returns per-node sync results.
    """
    import subprocess
    import sys
    import json
    from pathlib import Path

    # Extract the bearer token from the incoming Authorization header
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token required")

    script = Path(__file__).parent.parent.parent.parent / "scripts" / "sync_waf_rules.py"
    if not script.exists():
        raise HTTPException(status_code=500, detail=f"Sync script not found: {script}")

    try:
        result = subprocess.run(
            [sys.executable, str(script), "--token", token],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output_lines = result.stdout.strip().splitlines()

        # Try to parse results from sync log written by the script
        from services.rule_manager import RuleManager as _RM
        log_path = Path(__file__).parent.parent.parent.parent / "modsecurity" / "custom-rules" / "sync.log"
        last_result = None
        if log_path.exists():
            lines = log_path.read_text().strip().splitlines()
            if lines:
                last_result = json.loads(lines[-1])

        return {
            "status": "success" if result.returncode == 0 else "partial_failure",
            "exit_code": result.returncode,
            "output": output_lines,
            "node_results": last_result.get("results", []) if last_result else [],
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Sync script timed out (>60s)")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Sync failed: {exc}")

