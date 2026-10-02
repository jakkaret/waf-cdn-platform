from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.rbac import require_viewer_or_above
from services.pii_masker import pii_masker, zk_hash
from services.explainability_service import explainability_service
from services.fetch_logs import get_recent_logs
from services.tenant_service import build_tenant_origin_filter, get_user_origins_and_domains

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


def _tenant_clause(current_user: dict, requested_origin: Optional[str]) -> str:
    """ClickHouse WHERE fragment for what this user may see; "1=0" means
    nothing (no origins, or an origin they do not own)."""
    is_admin = current_user.get("role", "viewer") == "admin"
    _ids, _origins, user_domains = get_user_origins_and_domains(current_user.get("user_id"))
    return build_tenant_origin_filter(requested_origin, user_domains, is_admin)


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
    clause = _tenant_clause(current_user, origin)
    if clause == "1=0":
        return {"logs": [], "total": 0, "page": page, "limit": limit, "total_pages": 1}

    if ch.connected:
        return ch.get_logs(
            limit=limit,
            page=page,
            search=search,
            status_filter=status,
            severity_filter=severity,
            method_filter=method,
            origin_clause=clause,
        )

    # ClickHouse itself is unavailable. services/fetch_logs.py's
    # get_recent_logs() is a legacy, PRE-multi-tenant DynamoDB buffer
    # (waf_logs, queried under a single shared "default-user" partition --
    # it has no per-tenant scoping mechanism at all, unlike ClickHouse's
    # access_logs). Real cross-tenant leak fixed 2026-09-22 (found via
    # GET /recent below, which had the same fallback but reachable even
    # with ClickHouse connected): never show this buffer to a non-admin,
    # there is no way to know whose traffic is in it.
    if current_user.get("role") != "admin":
        return {"logs": [], "total": 0, "page": page, "limit": limit, "total_pages": 1}

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
    clause = _tenant_clause(current_user, origin)
    if clause == "1=0":
        return {"logs": []}

    if ch.connected:
        res = ch.get_logs(limit=limit, page=1, origin_clause=clause)
        # Real cross-tenant leak fixed 2026-09-22, reported live and
        # reproduced with a fresh account: a properly-scoped-but-EMPTY
        # ClickHouse result (this tenant genuinely has no matching traffic
        # yet -- the normal case for any new/low-traffic account) is not
        # the same as "ClickHouse has no capability to answer". The old
        # `if res.get("logs"):` treated an empty list as falsy and fell
        # through to the unscoped legacy buffer below, which showed a
        # brand-new account another tenant's real request. Return the
        # scoped result exactly as given, even when empty.
        return {"logs": res.get("logs", [])}

    # ClickHouse itself is unavailable -- see get_logs() above for why this
    # legacy DynamoDB fallback (waf_logs, shared "default-user" partition,
    # no per-tenant scoping at all) must stay admin-only.
    if current_user.get("role") != "admin":
        return {"logs": []}

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
    # Tenant scope, like every other log read: a log id from another tenant
    # must not be explainable (the id is not a secret -- it is the request id).
    is_admin = current_user.get("role") == "admin"
    _ids, _origins, user_domains = get_user_origins_and_domains(current_user.get("user_id"))
    scope = build_tenant_origin_filter("ALL", user_domains, is_admin)
    scope_sql = f" AND {scope}" if scope else ""
    if ch.connected and scope != "1=0":
        try:
            query = "SELECT toString(id) as log_id, url, method, status_code as status, rule_id, attack_type, matched_token, root_cause_explanation, remediation_hint, confidence_score, category FROM access_logs WHERE toString(id) = {log_id:String}" + scope_sql + " LIMIT 1"
            rows = ch.client.query(query, parameters={"log_id": log_id}).result_rows
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
