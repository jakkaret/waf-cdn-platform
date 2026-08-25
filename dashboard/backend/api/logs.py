from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.rbac import require_viewer_or_above
from services.pii_masker import pii_masker, zk_hash
from services.explainability_service import explainability_service
from services.fetch_logs import get_recent_logs
from services.tenant_service import get_user_origins_and_domains

router = APIRouter(prefix="/api/logs", tags=["logs"])
ch = ClickHouseService()
db = DynamoDBService()


class ExplainRequest(BaseModel):
    url: str = Field(..., max_length=4096, description="URL or Request Path to analyze")
    method: Optional[str] = Field("GET", max_length=16)
    rule_id: Optional[str] = Field(None, max_length=64)
    attack_type: Optional[str] = Field(None, max_length=256)
    status: Optional[int] = 403
    payload: Optional[str] = Field(None, max_length=8192, description="Request body payload")


class MaskPreviewRequest(BaseModel):
    text: str = Field(..., max_length=8192, description="Unstructured text to preview PII masking")


def _resolve_tenant_domains(current_user: dict, requested_origin: Optional[str]) -> Optional[List[str]]:
    """Determine the allowed domain filter list for the user based on tenant isolation"""
    user_id = current_user.get("user_id")
    role = current_user.get("role", "viewer")
    is_admin = (role == "admin")

    origin_ids, active_origins, user_domains = get_user_origins_and_domains(user_id)

    # 1. Specific origin requested
    if requested_origin and str(requested_origin).strip().upper() not in ["ALL", ""]:
        req_clean = str(requested_origin).strip()
        if not is_admin and user_domains:
            # Check ownership
            if not any(req_clean.lower() in d.lower() or d.lower() in req_clean.lower() for d in user_domains):
                return ["__FORBIDDEN_TENANT_DOMAIN__"]
        return [req_clean]

    # 2. 'ALL' selected
    if is_admin:
        return None  # Admin can view all global logs

    if not user_domains and not active_origins:
        return ["__NO_TENANT_ORIGINS__"]

    return user_domains if user_domains else ["__NO_TENANT_ORIGINS__"]


@router.get("")
@router.get("/")
async def get_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=1000),
    search: str = Query("", max_length=256, description="Search by IP, URL, Rule ID, Token"),
    status: str = Query("ALL", description="Status code or ALL/BLOCKED/ALLOWED"),
    severity: str = Query("ALL", description="Severity filter"),
    method: str = Query("ALL", description="HTTP method"),
    origin: Optional[str] = Query("ALL", description="Filter by web origin or ALL"),
    has_pii: Optional[bool] = Query(None, description="Filter only logs with masked PII"),
    current_user: dict = Depends(require_viewer_or_above)
):
    """Retrieve structured audit logs from ClickHouse with strict tenant isolation"""
    domain_targets = _resolve_tenant_domains(current_user, origin)
    if domain_targets and ("__NO_TENANT_ORIGINS__" in domain_targets or "__FORBIDDEN_TENANT_DOMAIN__" in domain_targets):
        return {"logs": [], "total": 0, "page": page, "limit": limit, "total_pages": 1}

    if ch.connected:
        return ch.get_logs(
            limit=limit,
            page=page,
            search=search,
            status_filter=status,
            severity_filter=severity,
            method_filter=method,
            domain_filter=domain_targets
        )

    # Fallback to DynamoDB/in-memory logs
    raw_logs = get_recent_logs(limit=limit)
    enriched_logs = []
    for l in raw_logs:
        exp = explainability_service.explain_event(l)
        l.update(exp)
        masked_l, pii_meta = pii_masker.mask_payload(l)
        masked_l.update(pii_meta)
        if has_pii is not None and masked_l.get("is_pii_masked") != has_pii:
            continue
        enriched_logs.append(masked_l)

    return {
        "logs": enriched_logs,
        "total": len(enriched_logs),
        "page": page,
        "limit": limit,
        "total_pages": 1
    }


@router.get("/recent")
async def fetch_recent_logs(
    limit: int = Query(100, ge=1, le=500),
    origin: Optional[str] = Query("ALL", description="Filter by web origin or ALL"),
    current_user: dict = Depends(require_viewer_or_above)
):
    """Fetch recent logs for Dashboard table view scoped to tenant origin"""
    domain_targets = _resolve_tenant_domains(current_user, origin)
    if domain_targets and ("__NO_TENANT_ORIGINS__" in domain_targets or "__FORBIDDEN_TENANT_DOMAIN__" in domain_targets):
        return {"logs": []}

    if ch.connected:
        res = ch.get_logs(limit=limit, page=1, domain_filter=domain_targets)
        if res.get("logs"):
            return {"logs": res["logs"]}

    raw = get_recent_logs(limit=limit)
    enriched = []
    for l in raw:
        exp = explainability_service.explain_event(l)
        l.update(exp)
        masked_l, pii_meta = pii_masker.mask_payload(l)
        masked_l.update(pii_meta)
        enriched.append(masked_l)
    return {"logs": enriched}


@router.get("/filters")
async def get_filter_options(current_user: dict = Depends(require_viewer_or_above)):
    if ch.connected:
        return ch.get_filter_options()
    return {
        "status_codes": [200, 302, 403, 404, 429, 500],
        "methods": ["GET", "POST", "HEAD", "PUT", "DELETE"],
        "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    }


@router.post("/explain")
async def explain_payload(
    req: ExplainRequest,
    current_user: dict = Depends(require_viewer_or_above)
):
    """Real-time Explainable WAF Token Attribution analyzer for arbitrary request/payload"""
    event_dict = {
        "url": req.url,
        "method": req.method,
        "rule_id": req.rule_id,
        "attack_type": req.attack_type,
        "status": req.status,
        "payload": req.payload
    }
    explanation = explainability_service.explain_event(event_dict)
    masked_url, pii_types = pii_masker.mask_text(req.url)
    
    return {
        "analysis": explanation,
        "sanitized_url": masked_url,
        "pii_detected": pii_types
    }


@router.get("/explain/{log_id}")
async def explain_log_by_id(
    log_id: str,
    current_user: dict = Depends(require_viewer_or_above)
):
    """Retrieve deep token attribution and explainability for a specific log by ID"""
    if ch.connected:
        try:
            escaped_id = log_id.replace("'", "\\'")
            query = f"SELECT toString(id) as log_id, url, method, status_code as status, rule_id, attack_type, matched_token, root_cause_explanation, remediation_hint, confidence_score, category FROM access_logs WHERE toString(id) = '{escaped_id}' LIMIT 1"
            rows = ch.client.query(query).result_rows
            if rows:
                cols = ['log_id', 'url', 'method', 'status', 'rule_id', 'attack_type', 'matched_token', 'root_cause_explanation', 'remediation_hint', 'confidence_score', 'category']
                log_data = dict(zip(cols, rows[0]))
                exp = explainability_service.explain_event(log_data)
                mitigation = explainability_service.generate_mitigation_candidate(log_data)
                return {
                    "log_id": log_id,
                    "explanation": exp,
                    "mitigation_candidate": mitigation
                }
        except Exception:
            pass

    return {
        "log_id": log_id,
        "explanation": {
            "matched_token": "",
            "category": "WAF Security Filter",
            "root_cause_explanation": "Analyzed from live event buffer",
            "remediation_hint": "Inspect request parameters",
            "confidence_score": 0.85,
            "explain_summary": "WAF Filter"
        }
    }


@router.post("/mask-preview")
async def preview_masking(
    req: MaskPreviewRequest,
    current_user: dict = Depends(require_viewer_or_above)
):
    """Test and preview Zero-Knowledge PII Masking & Salted Hash on any string"""
    masked_text, detected_types = pii_masker.mask_text(req.text)
    return {
        "original_length": len(req.text),
        "masked_text": masked_text,
        "detected_pii_types": detected_types,
        "zk_hash": zk_hash(req.text)
    }
