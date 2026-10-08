import asyncio
from typing import Optional, List, Dict, Any, Union
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field, field_validator
from services.rule_manager import RuleManager
from services.blast_radius_service import blast_radius_service
from services.bola_guard import bola_guard
from services.rbac import require_viewer_or_above, require_admin

router = APIRouter(prefix="/api/rules", tags=["rules"])
rule_manager = RuleManager()


from services.explainability_service import explainability_service
from services.bola_guard import validate_policy_regex


ALLOWED_ACTIONS = {"BLOCK", "CHALLENGE", "DECEIVE"}
ALLOWED_TEMPLATES = {"auto", "path_traversal", "sqli", "sql_injection"}


def validate_rule_action(v: Any) -> str:
    if v is None or v == "":
        return "BLOCK"
    if isinstance(v, str):
        v_upper = v.strip().upper()
        if v_upper in ALLOWED_ACTIONS:
            return v_upper
    valid_str = ", ".join(sorted(ALLOWED_ACTIONS))
    raise ValueError(f"action must be one of: {valid_str}")


def validate_rule_template(v: Any) -> str:
    if v is None or v == "":
        return "auto"
    if isinstance(v, str):
        v_lower = v.strip().lower()
        if v_lower in ALLOWED_TEMPLATES:
            return v_lower
    valid_str = ", ".join(sorted(ALLOWED_TEMPLATES))
    raise ValueError(f"deception_template must be one of: {valid_str}")


class RuleCreate(BaseModel):
    id: str
    variable: str
    operator: str
    severity: str
    message: str
    action: Optional[str] = Field(
        default="BLOCK",
        description="Rule action: BLOCK, CHALLENGE, or DECEIVE",
    )
    deception_template: Optional[str] = Field(
        default="auto",
        description="Deception template: auto, path_traversal, sqli, or sql_injection",
    )

    @field_validator("action", mode="before")
    @classmethod
    def check_action(cls, v: Any) -> str:
        return validate_rule_action(v)

    @field_validator("deception_template", mode="before")
    @classmethod
    def check_template(cls, v: Any) -> str:
        return validate_rule_template(v)


class RuleSchema(BaseModel):
    variable: str
    operator: str
    severity: str
    message: str
    action: Optional[str] = Field(
        default="BLOCK",
        description="Rule action: BLOCK, CHALLENGE, or DECEIVE",
    )
    deception_template: Optional[str] = Field(
        default="auto",
        description="Deception template: auto, path_traversal, sqli, or sql_injection",
    )

    @field_validator("action", mode="before")
    @classmethod
    def check_action(cls, v: Any) -> str:
        return validate_rule_action(v)

    @field_validator("deception_template", mode="before")
    @classmethod
    def check_template(cls, v: Any) -> str:
        return validate_rule_template(v)


RuleUpdate = RuleSchema


class RuleResponse(BaseModel):
    id: str
    variable: str
    operator: str
    severity: str
    message: str
    action: str = "BLOCK"
    deception_template: Optional[str] = "auto"


class BlastRadiusRequest(BaseModel):
    variable: Union[str, List[str]] = "REQUEST_URI"
    operator: str
    severity: str = "MEDIUM"
    time_range_hours: int = 24
    sample_limit: int = 2000
    rule_id: Optional[str] = None
    domain_id: Optional[str] = None
    anomaly_threshold: int = 5


class BolaPolicyCreate(BaseModel):
    id: Optional[str] = None
    name: str
    path_pattern: str
    claim_key: str = "sub"
    resource_type: str = "user_id"
    action: str = "BLOCK"
    allow_admin: bool = True
    description: Optional[str] = ""
    enabled: bool = True
    methods: Optional[List[str]] = ["ALL"]


class BolaPolicyUpdate(BaseModel):
    name: Optional[str] = None
    path_pattern: Optional[str] = None
    claim_key: Optional[str] = None
    resource_type: Optional[str] = None
    action: Optional[str] = None
    allow_admin: Optional[bool] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    methods: Optional[List[str]] = None


class BolaInspectRequest(BaseModel):
    path: str
    headers: Optional[Dict[str, str]] = {}
    method: str = "GET"


class MitigateCandidateRequest(BaseModel):
    url: str
    method: Optional[str] = "GET"
    rule_id: Optional[str] = None
    attack_type: Optional[str] = None
    status: Optional[int] = 403
    ip: Optional[str] = None
    payload: Optional[str] = None


# ==========================================
# 1. Custom WAF Rules Management
# ==========================================

@router.get("/")
async def get_rules(current_user: dict = Depends(require_admin)):
    # Legacy global custom rules (custom-*.conf) apply to *every* origin on
    # the WAF -- unlike managed rules (versioned, published from source) and
    # tenant rules (scoped to one origin via tx.waf_origin_id), there is no
    # per-origin ownership here to filter by. Any signed-in platform viewer
    # could see every dashboard-authored rule regardless of which origin(s)
    # they actually have access to; restricting to platform admin closes
    # that gap (access-control audit, 2026-09-28). New rule types should go
    # through api/managed_rules.py or api/tenant_rules.py instead of here.
    try:
        rules = rule_manager.list_rules()
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def create_rule(rule: RuleCreate, current_user: dict = Depends(require_admin)):
    try:
        success = rule_manager.add_rule(rule.model_dump())
        if success:
            return {"message": "Rule created", "rule_id": rule.id}
        raise HTTPException(status_code=500, detail="Failed to create rule")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    try:
        success = rule_manager.delete_rule(rule_id)
        if success:
            return {"message": "Rule deleted"}
        raise HTTPException(status_code=404, detail="Rule not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{rule_id}")
async def update_rule(rule_id: str, rule: RuleSchema, current_user: dict = Depends(require_admin)):
    try:
        rule_manager.update_rule(rule_id, rule.model_dump())
        return {"status": "updated", "rule_id": rule_id}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitigate-candidate")
async def generate_mitigation_candidate_rule(
    req: MitigateCandidateRequest,
    current_user: dict = Depends(require_viewer_or_above)
):
    """
    Analyzes an attack log or token and returns an auto-generated, ReDoS-safe candidate ModSecurity SecRule.
    """
    event = {
        "url": req.url,
        "method": req.method,
        "rule_id": req.rule_id,
        "attack_type": req.attack_type,
        "status": req.status,
        "ip": req.ip,
        "payload": req.payload
    }
    candidate = explainability_service.generate_mitigation_candidate(event)
    return {"success": True, **candidate}


@router.post("/sync")
async def sync_rules_to_edges(request: Request, current_user: dict = Depends(require_admin)):
    """Disabled (F-034). This ran scripts/sync_waf_rules.py, which wrote a
    dashboard-sync.conf duplicating every custom rule id into the shared rules
    dir; after one click every `nginx -t` failed on Main and, via the bundle,
    on every edge. Edges already pull the validated rule bundle on their own
    every few seconds, so there is nothing to trigger manually."""
    raise HTTPException(
        status_code=410,
        detail="Manual edge sync is disabled: edges pull the rule bundle automatically every few seconds.",
    )


# ==========================================
# 2. Blast Radius Simulator & Audit Export
# ==========================================

@router.post("/blast-radius")
async def simulate_blast_radius(payload: BlastRadiusRequest, current_user: dict = Depends(require_admin)):
    """
    Replays historical traffic against candidate rule to estimate false positives and blast radius.

    Admin only (2026-09-28): the replay covers every tenant's real traffic and
    returns sample URLs and client IPs; rules themselves are admin-managed.
    Supports Multi-Variable rules, Multi-CIDR @ipMatch operators, and Domain/Tenant filtering.
    """
    try:
        result = await asyncio.to_thread(
            blast_radius_service.simulate,
            variable=payload.variable,
            operator=payload.operator,
            severity=payload.severity,
            time_range_hours=payload.time_range_hours,
            sample_limit=payload.sample_limit,
            rule_id=payload.rule_id,
            domain_id=payload.domain_id,
            anomaly_threshold=payload.anomaly_threshold
        )
        if result.get("success") is False:
            raise HTTPException(
                status_code=422,
                detail=result.get("error", "Rule validation or ReDoS vulnerability detected")
            )
        return result
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/blast-radius/export")
async def export_blast_radius_audit(payload: BlastRadiusRequest, current_user: dict = Depends(require_admin)):
    """
    Generates and exports an Enterprise SecOps Compliance Audit Report for the simulated rule.
    """
    try:
        sim_result = await asyncio.to_thread(
            blast_radius_service.simulate,
            variable=payload.variable,
            operator=payload.operator,
            severity=payload.severity,
            time_range_hours=payload.time_range_hours,
            sample_limit=payload.sample_limit,
            rule_id=payload.rule_id,
            domain_id=payload.domain_id,
            anomaly_threshold=payload.anomaly_threshold
        )
        if sim_result.get("success") is False:
            raise HTTPException(
                status_code=422,
                detail=sim_result.get("error", "Rule simulation failed during audit generation")
            )
        audit_report = blast_radius_service.generate_audit_report(sim_result)
        return {"success": True, "report": audit_report, "simulation": sim_result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# 3. Context-Aware BOLA / IDOR Guard API
# ==========================================

@router.get("/bola/policies")
async def get_bola_policies(current_user: dict = Depends(require_viewer_or_above)):
    """List active BOLA protection policies."""
    return {"policies": bola_guard.list_policies()}


@router.post("/bola/policies")
async def create_bola_policy(policy: BolaPolicyCreate, current_user: dict = Depends(require_admin)):
    """Add or update a BOLA protection policy."""
    is_valid, err_msg = validate_policy_regex(policy.path_pattern)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid BOLA policy regex: {err_msg}")

    success = bola_guard.add_policy(policy.dict(), persist=True)
    if success:
        return {"success": True, "message": "BOLA Policy configured successfully"}
    raise HTTPException(status_code=400, detail="Invalid BOLA policy configuration")


@router.put("/bola/policies/{policy_id}")
async def update_bola_policy(policy_id: str, updates: BolaPolicyUpdate, current_user: dict = Depends(require_admin)):
    """Update an existing BOLA protection policy."""
    update_data = {k: v for k, v in updates.dict().items() if v is not None}
    if "path_pattern" in update_data:
        is_valid, err_msg = validate_policy_regex(update_data["path_pattern"])
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid BOLA policy regex: {err_msg}")

    success = bola_guard.update_policy(policy_id, update_data, persist=True)
    if success:
        return {"success": True, "message": f"BOLA Policy {policy_id} updated"}
    raise HTTPException(status_code=404, detail=f"BOLA Policy {policy_id} not found")


@router.delete("/bola/policies/{policy_id}")
async def delete_bola_policy(policy_id: str, current_user: dict = Depends(require_admin)):
    """Delete a BOLA protection policy."""
    success = bola_guard.remove_policy(policy_id, persist=True)
    if success:
        return {"success": True, "message": f"BOLA Policy {policy_id} removed"}
    raise HTTPException(status_code=404, detail="BOLA Policy not found")


@router.post("/bola/inspect")
async def inspect_request_bola(req: BolaInspectRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Test/Inspect a request path and headers against BOLA guard engine."""
    result = bola_guard.inspect_request(
        path=req.path,
        headers=req.headers or {},
        method=req.method,
        verified_user=current_user
    )
    return result
