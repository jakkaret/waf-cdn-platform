"""
T12 -- self-tuning anomaly-threshold proposal API.

Mirrors api/ml_rules.py's admin-gated pending-approval pattern. The only two
endpoints that can ever change the live WAF threshold are /approve and
/rollback, both require_admin, both delegate to
ThresholdProposalStore.approve()/rollback() which call
SettingsService.update_settings() -- there is no endpoint that applies a
proposal's threshold automatically or without an explicit admin action.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services.clickhouse_service import ClickHouseService
from services.rbac import require_admin, require_viewer_or_above
from services.settings_service import SettingsService
from services.tenant_service import get_user_origins_and_domains, is_origin_owned
from services.threshold_proposal_service import (
    ThresholdProposalStore,
    generate_threshold_proposal,
)

router = APIRouter(prefix="/api/threshold-proposals", tags=["Self-Tuning Threshold"])
store = ThresholdProposalStore()
settings_service = SettingsService()
ch = ClickHouseService()


class RejectRequest(BaseModel):
    reason: Optional[str] = ""


@router.post("/generate")
async def generate_proposal(lookback_hours: int = 24, current_user: dict = Depends(require_admin)):
    """Analyzes recent ClickHouse block-rate evidence and, if it clears the
    safety bar (see services/threshold_proposal_service.py's module
    docstring), stores a new pending proposal. Returns null if there is
    nothing safe to propose right now -- this is not an error, and callers
    must not treat "no proposal" as a failure.
    """
    current_threshold = settings_service.get_settings().get("inbound_anomaly_threshold", 10)
    proposal = generate_threshold_proposal(ch, current_threshold, lookback_hours=lookback_hours)
    if proposal is None:
        return {"proposal": None, "message": "No safe proposal for the current data (see server logs for why)."}

    created = store.create(proposal, created_by=current_user.get("username", "system"))
    return {"proposal": created}


def _scope_for_viewer(proposal: dict, current_user: dict) -> dict:
    """Admins see the full evidence. Anyone else sees only their own origins'
    rows: the evidence lists every tenant's hostname with request volume and
    block rate, which is not theirs to see (2026-09-28)."""
    if current_user.get("role") == "admin" or not isinstance(proposal, dict):
        return proposal
    _ids, _origins, user_domains = get_user_origins_and_domains(current_user.get("user_id"))
    evidence = dict(proposal.get("evidence") or {})
    rows = evidence.get("origins") or []
    own = [r for r in rows if is_origin_owned(str(r.get("origin", "")), user_domains)]
    evidence["origins"] = own
    evidence["corroborating_origins"] = [
        o for o in evidence.get("corroborating_origins") or [] if is_origin_owned(str(o), user_domains)
    ]
    evidence["hidden_origin_count"] = len(rows) - len(own)
    return {**proposal, "evidence": evidence}


@router.get("/")
async def list_proposals(status: Optional[str] = None, current_user: dict = Depends(require_viewer_or_above)):
    return {"proposals": [_scope_for_viewer(p, current_user) for p in store.list(status)]}


@router.get("/{proposal_id}")
async def get_proposal(proposal_id: str, current_user: dict = Depends(require_viewer_or_above)):
    proposal = store.get(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return _scope_for_viewer(proposal, current_user)


@router.post("/{proposal_id}/approve")
async def approve_proposal(proposal_id: str, current_user: dict = Depends(require_admin)):
    try:
        proposal = store.approve(proposal_id, approved_by=current_user.get("username", "admin"), settings_service=settings_service)
        return {"message": "Proposal approved and applied", "proposal": proposal}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{proposal_id}/reject")
async def reject_proposal(proposal_id: str, req: RejectRequest, current_user: dict = Depends(require_admin)):
    try:
        proposal = store.reject(proposal_id, rejected_by=current_user.get("username", "admin"), reason=req.reason)
        return {"message": "Proposal rejected", "proposal": proposal}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{proposal_id}/rollback")
async def rollback_proposal(proposal_id: str, current_user: dict = Depends(require_admin)):
    """Reverts an approved proposal's threshold change back to whatever was
    live immediately before it was approved (recorded by approve() itself,
    not re-derived)."""
    try:
        proposal = store.rollback(proposal_id, rolled_back_by=current_user.get("username", "admin"), settings_service=settings_service)
        return {"message": "Proposal rolled back", "proposal": proposal}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
