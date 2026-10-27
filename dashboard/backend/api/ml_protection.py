"""A site's ML protection setting (2026-10-27): log only, or enforce with a
challenge band and a block band on the Gen 3 score (services/ml_gate.py).

Owner and Editors change it, Viewers read it, nobody else sees it (the same
/api/origins/{origin_id} access rules as IP access and rate limits). Every
change goes to the site's audit log in the same transaction. The preview reads
the site's own scored traffic (ClickHouse ml_verdicts) to show what a setting
would have challenged or blocked before anyone turns it on."""
import asyncio
import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.ml import ch
from services import audit_log, ml_gate, ml_verdicts
from services.dynamodb_service import DynamoDBService
from services.rbac import get_current_user, verify_origin_access, verify_origin_edit_access
from services.tenant_service import origin_traffic_filter
from services.txn import atomic

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/origins/{origin_id}", tags=["ml-protection"])
db = DynamoDBService()


class MlProtectionIn(BaseModel):
    mode: Literal["log", "enforce"]
    challenge_score: Optional[int] = Field(None, ge=ml_gate.CHALLENGE_RANGE[0], le=ml_gate.CHALLENGE_RANGE[1],
                                           description="empty = no challenge band")
    block_score: int = Field(..., ge=ml_gate.BLOCK_RANGE[0], le=ml_gate.BLOCK_RANGE[1])


def _hosts(origin_id: str) -> list:
    from services.shield_sync import desired_hostmap
    return sorted(h for h, oid in desired_hostmap(db).items() if oid == str(origin_id))


def _view(origin_id: str) -> dict:
    settings = ml_gate.get_settings(origin_id)
    hosts = _hosts(origin_id)
    in_map = ml_gate.hosts_in_map(ml_gate.read_map())
    want = (ml_gate.policy_value(settings["challenge_score"], settings["block_score"])
            if settings["mode"] == "enforce" else None)
    # Live = every host of the site is in the WAF's map exactly as saved (or,
    # in log mode, none of them is).
    applied = all(in_map.get(h) == want for h in hosts)
    return {**settings, "hosts": hosts, "applied": applied, "map_error": ml_gate.status()["last_error"]}


@router.get("/ml-protection")
async def get_ml_protection(origin: dict = Depends(verify_origin_access)):
    return await asyncio.to_thread(_view, origin["id"])


def _band_text(s: dict) -> str:
    if s["mode"] != "enforce":
        return "log อย่างเดียว"
    challenge = f"challenge ตั้งแต่ {s['challenge_score']}" if s["challenge_score"] else "ไม่มี challenge"
    return f"enforce: {challenge}, block ตั้งแต่ {s['block_score']}"


@router.put("/ml-protection")
async def put_ml_protection(body: MlProtectionIn, origin: dict = Depends(verify_origin_edit_access),
                            current_user: dict = Depends(get_current_user)):
    by = current_user.get("username") or current_user.get("user_id") or ""

    def run():
        with atomic():
            previous, saved = ml_gate.save_settings(origin["id"], body.mode, body.challenge_score,
                                                    body.block_score, by)
            audit_log.write_audit_event(
                scope_id=origin["id"], actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""), action="ml_protection.update",
                summary=f"ML protection: {_band_text(previous)} -> {_band_text(saved)}",
                details={"before": {k: previous[k] for k in ("mode", "challenge_score", "block_score")},
                         "after": {k: saved[k] for k in ("mode", "challenge_score", "block_score")}},
            )
        # Saved either way; a map that nginx refused stays as it was (log mode
        # for anything new) and the worker retries.
        ml_gate.sync_quietly(db)
        return _view(origin["id"])

    try:
        return await asyncio.to_thread(run)
    except ml_gate.MlProtectionError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/ml-protection/preview")
async def preview_ml_protection(
    block_score: int = Query(..., ge=ml_gate.BLOCK_RANGE[0], le=ml_gate.BLOCK_RANGE[1]),
    challenge_score: Optional[int] = Query(None, ge=ml_gate.CHALLENGE_RANGE[0], le=ml_gate.CHALLENGE_RANGE[1]),
    hours: int = Query(168, ge=1, le=168),
    origin: dict = Depends(verify_origin_access),
):
    if challenge_score is not None and challenge_score >= block_score:
        raise HTTPException(status_code=422, detail="challenge score must be lower than the block score")
    # The origin's own verified hosts (access was checked above), "1=0" when it has none.
    scope = await asyncio.to_thread(origin_traffic_filter, origin["id"])
    if scope == "1=0":
        return {"hours": hours, "total": 0, "would_block": 0, "would_challenge": 0, "since": None, "examples": []}
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    try:
        return await asyncio.to_thread(ml_gate.preview, ch, scope, challenge_score, block_score, hours)
    except Exception as exc:
        logger.warning("ML protection preview failed: %s", exc)
        raise HTTPException(status_code=503, detail="analytics store unavailable")


# ---- one scored request: its masked body, and a rule from it ------------------
#
# ML Insights (2026-10-27) replaced the page where a request was pasted in by
# hand: an Owner or Editor opens a flagged request of their own origin and asks
# Gen 3 for a rule from it. The rule joins the origin's pending queue
# (api/ml_rules.py), where it is backtested and approved or rejected like any
# other; nothing here deploys anything. Viewers never see the body.

def _verdict_of(origin_id: str, request_id: str) -> dict:
    scope = origin_traffic_filter(origin_id)
    if scope == "1=0":
        raise HTTPException(status_code=404, detail="Request not found")
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    try:
        verdict = ml_verdicts.get_verdict(ch, scope, request_id)
    except Exception as exc:
        logger.warning("ML verdict lookup failed: %s", exc)
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    if not verdict:
        raise HTTPException(status_code=404, detail="Request not found")
    return verdict


@router.get("/ml-verdicts/{request_id}")
async def get_ml_verdict(request_id: str, origin: dict = Depends(verify_origin_edit_access)):
    """One of this origin's scored requests with its masked body sample
    (kept from score 50 up). Owner and Editors only."""
    return await asyncio.to_thread(_verdict_of, origin["id"], request_id)


@router.post("/ml-verdicts/{request_id}/suggest-rule")
async def suggest_rule_from_verdict(request_id: str, origin: dict = Depends(verify_origin_edit_access),
                                    current_user: dict = Depends(get_current_user)):
    """Ask Gen 3 for a rule from one flagged request of this origin, rescored
    from what was stored (path, redacted query, masked body). Only for a
    request Gen 3 flagged and the inline gate did not block. Proposals go to
    this origin's pending queue for review."""
    from api import ml as ml_api
    from api.ml_rules import _with_access
    from services.rbac import origin_role

    verdict = await asyncio.to_thread(_verdict_of, origin["id"], request_id)
    if verdict["action"] == "block":
        raise HTTPException(status_code=409, detail="ML already blocks this request; a rule would add nothing")
    if not verdict["is_attack"]:
        raise HTTPException(status_code=422, detail="This request scored below the model threshold, so Gen 3 proposes no rule")
    ml_api._check_suggest_quota(str(current_user.get("user_id") or "unknown"))
    url = verdict["path"] + (f"?{verdict['query']}" if verdict["query"] else "")
    req = ml_api.PredictRequest(url=url, method=verdict["method"], body=verdict["body_sample"])
    try:
        async with ml_api.httpx.AsyncClient() as client:
            gen3 = await ml_api._gen3_verdict(client, req)
            rules, reason = await ml_api._proposed_rules(client, req, gen3)
    except ml_api.httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {exc}")
    suggested, created, merged = await asyncio.to_thread(ml_api._queue_proposals, rules, origin, current_user)
    role = origin_role(origin, current_user.get("user_id"))
    is_admin = current_user.get("role") == "admin"
    return {
        "gen3": gen3,
        "suggested_rules": [_with_access(r, is_admin, role) for r in suggested],
        "suggestion": {"created": created, "merged": merged, "reason": reason, "origin_id": origin["id"]},
    }
