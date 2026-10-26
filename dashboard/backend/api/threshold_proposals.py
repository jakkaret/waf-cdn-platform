"""
Per-origin anomaly-threshold tuning proposals.

Who may do what (2026-10-27):
  Owner of the origin   generate, approve, reject, roll back
  Editor / Viewer       read the origin's proposals
  anyone else           404, platform admins included: tuning an origin's
                        threshold is that Owner's decision only

The only endpoints that change a threshold are /approve and /rollback, and
both go through ThresholdProposalStore, which changes that one origin's
value and rewrites its host-map rule. Nothing is applied automatically.
"""
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services import audit_log, managed_ruleset
from services.clickhouse_service import ClickHouseService
from services.rbac import ARCHIVED_ORIGIN_STATUSES, origin_role, require_viewer_or_above
from services.settings_service import SettingsService
from services.threshold_proposal_service import (
    LOOKBACK_HOURS_DEFAULT,
    ThresholdProposalStore,
    effective_threshold,
    generate_origin_threshold_proposal,
)

router = APIRouter(prefix="/api/threshold-proposals", tags=["Self-Tuning Threshold"])
store = ThresholdProposalStore()
settings_service = SettingsService()
ch = ClickHouseService()

OWNER_ONLY = "Only the origin's Owner can do this"


class RejectRequest(BaseModel):
    reason: Optional[str] = ""


def _platform_threshold() -> int:
    return int(settings_service.get_settings().get("inbound_anomaly_threshold", 10))


def _member_origins(user: dict) -> List[Tuple[dict, str]]:
    # Read straight from the store: origin_service.get_origins_visible_to_user
    # caches owned origins, which would show a just-approved threshold late.
    uid = user.get("user_id")
    if not uid:
        return []
    owned = store.db.get_origins_by_user(uid)
    owned_ids = {o.get("id") for o in owned}
    try:
        shared = store.db.get_origins_shared_with(uid)
    except Exception:
        shared = []
    out = []
    for origin in owned + [o for o in shared if o.get("id") not in owned_ids]:
        if origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
            continue
        role = origin_role(origin, uid)
        if role:
            out.append((origin, role))
    return out


def _origin_for(origin_id: str, user: dict, owner: bool) -> Tuple[dict, str]:
    """The origin and the caller's role; 404 for non-members (they may not
    learn it exists), 403 when an action needs the Owner."""
    origin = store.db.get_origin_by_id(origin_id) if origin_id else None
    role = origin_role(origin, user.get("user_id")) if origin else None
    if not origin or not role or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        raise HTTPException(status_code=404, detail="Origin not found")
    if owner and role != "owner":
        raise HTTPException(status_code=403, detail=OWNER_ONLY)
    return origin, role


def _proposal_for(proposal_id: str, user: dict, owner: bool) -> Tuple[dict, dict]:
    proposal = store.get(proposal_id)
    if not proposal or not proposal.get("origin_id"):
        raise HTTPException(status_code=404, detail="Proposal not found")
    try:
        origin, _ = _origin_for(proposal["origin_id"], user, owner)
    except HTTPException as e:
        if e.status_code == 404:
            raise HTTPException(status_code=404, detail="Proposal not found")
        raise
    return proposal, origin


def _with_access(proposal: dict, role: str) -> dict:
    return {**proposal, "can_review": role == "owner"}


def _audit(user: dict, origin_id: str, action: str, summary: str, proposal: dict) -> None:
    audit_log.write_audit_event(
        scope_id=origin_id,
        actor_user_id=user.get("user_id"),
        actor_username=user.get("username", ""),
        action=action,
        summary=summary,
        details={"proposal_id": proposal.get("proposal_id"),
                 "current_threshold": proposal.get("current_threshold"),
                 "proposed_threshold": proposal.get("proposed_threshold")},
    )


@router.get("/origins")
async def list_tunable_origins(current_user: dict = Depends(require_viewer_or_above)):
    """Origins the caller belongs to, with the threshold the WAF applies to each."""
    platform = _platform_threshold()
    _, hosts = managed_ruleset.verified_hosts_by_origin(store.db)
    return {
        "platform_threshold": platform,
        "origins": [
            {
                "origin_id": o["id"],
                "label": o.get("label"),
                "role": role,
                "hosts": sorted(hosts.get(str(o["id"]), [])),
                "anomaly_threshold": o.get("anomaly_threshold"),
                "effective_threshold": effective_threshold(o, platform),
            }
            for o, role in _member_origins(current_user)
        ],
    }


@router.post("/generate")
async def generate_proposal(origin_id: str, lookback_hours: int = LOOKBACK_HOURS_DEFAULT,
                            current_user: dict = Depends(require_viewer_or_above)):
    """Owner of the origin only: analyses its own block rate and, if it clears the bar (see
    services/threshold_proposal_service.py), stores a pending proposal.
    "No proposal" comes back with the reason; it is not an error."""
    origin, role = _origin_for(origin_id, current_user, owner=True)
    if not 1 <= lookback_hours <= 24 * 30:
        raise HTTPException(status_code=400, detail="lookback_hours must be between 1 and 720")
    if store.list("pending", [origin["id"]]):
        return {"proposal": None, "message": "This origin already has a pending proposal. Approve or reject it first."}
    _, hosts = managed_ruleset.verified_hosts_by_origin(store.db)
    proposal, why = generate_origin_threshold_proposal(
        ch, origin["id"], hosts.get(str(origin["id"]), []),
        effective_threshold(origin, _platform_threshold()), lookback_hours=lookback_hours,
    )
    if proposal is None:
        return {"proposal": None, "message": why}
    created = store.create(proposal, created_by=current_user.get("username", ""))
    _audit(current_user, origin["id"], "threshold.propose",
           f"สร้าง tuning proposal: threshold {created['current_threshold']} -> {created['proposed_threshold']}", created)
    return {"proposal": _with_access(created, role)}


@router.get("/")
async def list_proposals(status: Optional[str] = None, origin_id: Optional[str] = None,
                         current_user: dict = Depends(require_viewer_or_above)):
    roles: Dict[str, str] = {str(o["id"]): role for o, role in _member_origins(current_user)}
    if origin_id:
        if origin_id not in roles:
            raise HTTPException(status_code=404, detail="Origin not found")
        roles = {origin_id: roles[origin_id]}
    proposals = store.list(status, list(roles))
    return {"proposals": [_with_access(p, roles.get(p["origin_id"], "viewer")) for p in proposals]}


@router.get("/{proposal_id}")
async def get_proposal(proposal_id: str, current_user: dict = Depends(require_viewer_or_above)):
    proposal, origin = _proposal_for(proposal_id, current_user, owner=False)
    return _with_access(proposal, origin_role(origin, current_user.get("user_id")))


@router.post("/{proposal_id}/approve")
async def approve_proposal(proposal_id: str, current_user: dict = Depends(require_viewer_or_above)):
    """Owner of the proposal's origin only: applies the threshold to that origin."""
    _proposal_for(proposal_id, current_user, owner=True)
    try:
        proposal = store.approve(proposal_id, approved_by=current_user.get("username", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(current_user, proposal["origin_id"], "threshold.approve",
           f"อนุมัติ tuning proposal: threshold ของ origin นี้เป็น {proposal['proposed_threshold']}", proposal)
    return {"message": "Proposal approved and applied to this origin", "proposal": _with_access(proposal, "owner")}


@router.post("/{proposal_id}/reject")
async def reject_proposal(proposal_id: str, req: RejectRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Owner of the proposal's origin only."""
    _proposal_for(proposal_id, current_user, owner=True)
    try:
        proposal = store.reject(proposal_id, rejected_by=current_user.get("username", ""), reason=req.reason or "")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(current_user, proposal["origin_id"], "threshold.reject", "ปฏิเสธ tuning proposal", proposal)
    return {"message": "Proposal rejected", "proposal": _with_access(proposal, "owner")}


@router.post("/{proposal_id}/rollback")
async def rollback_proposal(proposal_id: str, current_user: dict = Depends(require_viewer_or_above)):
    """Owner of the proposal's origin only: puts back the origin's threshold
    from just before the approval (its own value, or the platform threshold)."""
    _proposal_for(proposal_id, current_user, owner=True)
    try:
        proposal = store.rollback(proposal_id, rolled_back_by=current_user.get("username", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(current_user, proposal["origin_id"], "threshold.rollback", "ย้อน tuning proposal กลับเป็นค่าก่อนอนุมัติ", proposal)
    return {"message": "Proposal rolled back", "proposal": _with_access(proposal, "owner")}
