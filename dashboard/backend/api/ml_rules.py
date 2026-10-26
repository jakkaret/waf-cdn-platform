"""ML / CVE rule proposals: review queue and approval.

Who sees and reviews what (2026-10-26):
  - A rule with an origin_id belongs to that origin. Its Owner, Editors and
    Viewers see it; its Owner and Editors may approve or reject it; nobody
    else learns it exists (404, not 403). Approving it -- whoever approves,
    the platform admin included -- deploys it scoped to that origin only
    (rule_manager.scope_ml_rule_to_origin): it fires only for requests the
    WAF host map attributed to that origin, like tenant rules.
  - A rule without an origin_id (the global queue) is the platform admin's
    only, and deploys for every origin, as before.
  - The platform admin (role "admin") sees and reviews every rule. Deleting
    rules, the legacy bulk reject and the CVE scan of every origin stay
    admin-only.
  - 2026-10-27: an approved rule can be revoked (POST /{rule_id}/revoke):
    its file leaves the WAF, the row stays as a record. The admin may revoke
    any; an origin's Owner/Editors only one that runs for their origin alone
    (deploy_scope "origin") -- a rule written for every origin protects other
    tenants too. An origin's Owner/Editors may also run the CVE scan for their
    own origin (POST /cve-scan?origin_id=...), rate-limited per origin.
Rules are only ever deployed through POST /{rule_id}/approve.
"""
import re
import httpx
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Optional, Tuple
from services.dynamodb_service import DynamoDBService
from services.ml_rule_service import MLRuleService
from services.rbac import ARCHIVED_ORIGIN_STATUSES, origin_role, require_admin, require_viewer_or_above
from services import audit_log, rule_backtest
from services.txn import atomic
from services.cve_feed import DEFAULT_WINDOW_DAYS, fetch_recent_cves, match_cves_to_origins, select_search_terms
from services.gemini_service import gemini_service
from services.rule_manager import escape_secrule_message, escape_secrule_operator

router = APIRouter(prefix="/api/ml-rules", tags=["ml-rules"])
rule_service = MLRuleService()
# Origin membership is read here, not through rule_service.db, so tests that
# replace rule_service with a mock still resolve real roles.
_store = DynamoDBService()
AUDIT_SCOPE_GLOBAL = "global"
REVIEW_ROLES = ("owner", "editor")
NOT_FOUND = "Rule not found"

# CVE Auto-Patch (2026-09-22). Hard cap, not a magic number buried in the
# loop: the pending-rules queue already has ~268 unreviewed items as of
# this writing, and a scan that dumps dozens more into it in one call makes
# the product worse, not better. Approval is the real bottleneck here, not
# proposal generation. Counted per (CVE, origin) proposal since 2026-10-26:
# the rest of a scan's matches come back on the next scan.
CVE_SCAN_MAX_PROPOSALS = 5
CVE_SCAN_DEFAULT_WINDOW_DAYS = DEFAULT_WINDOW_DAYS
# A scan of one origin by its Owner/Editor (2026-10-27): every scan calls NVD
# and Gemini, so each origin gets a few per hour, counted per origin (not per
# user, so an origin's members share it). The platform-wide scan is not capped.
CVE_SCAN_ORIGIN_LIMIT_PER_HOUR = 3
_cve_scan_limiter = None

class RuleRejectRequest(BaseModel):
    reason: Optional[str] = ""


class RuleRevokeRequest(BaseModel):
    reason: Optional[str] = ""


def _is_admin(user: dict) -> bool:
    return user.get("role") == "admin"


def _member_roles(user_id: Optional[str]) -> Dict[str, str]:
    """{origin_id: role} for every live origin the user is Owner, Editor or
    Viewer of. Read fresh on every call: a member just removed loses the
    rules at once (origin_service's per-user list is cached)."""
    roles: Dict[str, str] = {}
    if not user_id:
        return roles
    for origin in _store.get_origins_by_user(user_id) + _store.get_origins_shared_with(user_id):
        oid = str(origin.get("id") or "")
        if oid and oid not in roles and origin.get("status") not in ARCHIVED_ORIGIN_STATUSES:
            role = origin_role(origin, user_id)
            if role:
                roles[oid] = role
    return roles


def _role_for_rule(rule: dict, user: dict) -> Optional[str]:
    """The caller's role on the rule's origin; None for a global rule, an
    archived/deleted origin, or a non-member."""
    oid = rule.get("origin_id") or ""
    if not oid:
        return None
    origin = _store.get_origin_by_id(oid)
    if not origin or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        return None
    return origin_role(origin, user.get("user_id"))


def _deploy_scope(rule: dict) -> str:
    """Where the rule runs: for an approved rule, how approval actually wrote
    its file (recorded since migration 0018; every rule approved before it was
    written global, CVE rules with an origin_id included); for any other, where
    approving it would put it, which follows origin_id."""
    if rule.get("status") == "approved" and rule.get("deploy_scope") in ("origin", "global"):
        return rule["deploy_scope"]
    return "origin" if rule.get("origin_id") else "global"


def _may_revoke(rule: dict, is_admin: bool, role: Optional[str]) -> bool:
    """An approved rule: the admin may revoke any; an origin's Owner/Editors
    only one written for their origin alone."""
    if rule.get("status") != "approved":
        return False
    return is_admin or (role in REVIEW_ROLES and _deploy_scope(rule) == "origin")


def _with_access(rule: dict, is_admin: bool, role: Optional[str]) -> dict:
    """The rule plus what the caller may do with it (the UI shows buttons from these)."""
    oid = rule.get("origin_id") or ""
    may_edit = is_admin or role in REVIEW_ROLES
    return {
        **rule,
        "origin_id": oid,
        "origin_label": rule.get("origin_label") or "",
        "can_review": may_edit and rule.get("status") == "pending",
        "can_backtest": may_edit and rule_backtest.can_backtest(rule),
        "can_revoke": _may_revoke(rule, is_admin, role),
        "deploy_scope": _deploy_scope(rule),
    }


def _visible_rule(rule_id: str, user: dict) -> Tuple[dict, Optional[str]]:
    """(rule, caller's origin role) or 404 -- for a missing rule and for one
    the caller may not see alike, so its existence does not leak."""
    rule = rule_service.get_rule_detail(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    if _is_admin(user):
        return rule, None
    role = _role_for_rule(rule, user)
    if role is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return rule, role


def _reviewable_rule(rule_id: str, user: dict) -> Tuple[dict, Optional[str]]:
    rule, role = _visible_rule(rule_id, user)
    if not _is_admin(user) and role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Owner or Editor of this origin required")
    return rule, role


def _audit_scope(rule: dict) -> str:
    """An origin's rule is recorded in that origin's audit log (its owner is
    told when someone else changed it, services/site_alerts.py); a global
    rule in the platform log."""
    return (rule.get("origin_id") if isinstance(rule, dict) else "") or AUDIT_SCOPE_GLOBAL


@router.get("/")
async def list_ml_rules(status: Optional[str] = None, current_user: dict = Depends(require_viewer_or_above)):
    """Platform admin: every rule. Anyone else: the rules of origins they are Owner, Editor or Viewer of.

    2026-10-26: was admin-only because the queue had no per-tenant field;
    rows now carry origin_id (CVE scan: the origin whose tech stack matched;
    ML analyst: the origin its Owner/Editor picked). A rule with no origin_id
    (the global queue, deployed for every origin) is never shown to a
    non-admin, nor are rules of an archived/deleted origin. Each rule carries
    can_review / can_backtest / deploy_scope for the caller.
    """
    is_admin = _is_admin(current_user)
    try:
        if is_admin:
            rules = [_with_access(r, True, None) for r in rule_service.list_rules(status)]
        else:
            roles = _member_roles(current_user.get("user_id"))
            rules = [_with_access(r, False, roles.get(r.get("origin_id") or ""))
                     for r in (rule_service.list_rules(status, origin_ids=list(roles)) if roles else [])]
        return {"rules": rules, "is_admin": is_admin}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{rule_id}")
async def get_ml_rule(rule_id: str, current_user: dict = Depends(require_viewer_or_above)):
    """Platform admin, or a member of the rule's origin; anyone else gets 404 (see list_ml_rules)."""
    rule, role = _visible_rule(rule_id, current_user)
    return _with_access(rule, _is_admin(current_user), role)

@router.post("/{rule_id}/approve")
async def approve_ml_rule(rule_id: str, current_user: dict = Depends(require_viewer_or_above)):
    """Approve and deploy: platform admin, or Owner/Editor of the rule's origin (deployed for that origin only)."""
    checked, _role = _reviewable_rule(rule_id, current_user)

    def _audit(action: str, rule: dict, summary: str) -> None:
        audit_log.write_audit_event(
            scope_id=_audit_scope(rule),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action=action,
            summary=summary,
            details={
                "rule_id": rule_id,
                "attack_type": rule.get("attack_type") if isinstance(rule, dict) else None,
                "deployed_rule_id": rule.get("deployed_rule_id") if isinstance(rule, dict) else None,
                "deploy_scope": "origin" if _audit_scope(rule) != AUDIT_SCOPE_GLOBAL else "global",
            },
        )

    scope_note = " (เฉพาะ origin นี้)" if checked.get("origin_id") else ""
    try:
        # approve_rule records "rule.approve" in the same transaction as the
        # status change (PostgreSQL), deploys the file after commit, and
        # records "rule.approve_failed" when the deploy fails. The origin the
        # caller was checked against must still be the rule's origin.
        rule = rule_service.approve_rule(
            rule_id, approved_by=current_user.get("username", "admin"),
            on_approved=lambda r: _audit("rule.approve", r, f"อนุมัติ+deploy ML rule{scope_note}: {rule_id}"),
            on_deploy_failed=lambda r, err: _audit(
                "rule.approve_failed", r, f"deploy ML rule ไม่สำเร็จ คืนสถานะเป็น pending: {rule_id} ({err})"),
            expected_origin_id=checked.get("origin_id") or "",
        )
        return {"message": "Rule approved and deployed", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

LEGACY_REJECT_REASON = "กฎแบบเก่าจาก RandomForest: ระบบเปลี่ยนมาใช้ Gen 3 แล้ว"


@router.post("/reject-legacy")
async def reject_legacy_ml_rules(current_user: dict = Depends(require_admin)):
    """Reject every pending "rf-regex" rule in one call (the queue's ~268 RF leftovers)."""
    try:
        with atomic():
            result = rule_service.reject_legacy_pending(
                rejected_by=current_user.get("username", "admin"), reason=LEGACY_REJECT_REASON
            )
            audit_log.write_audit_event(
                scope_id=AUDIT_SCOPE_GLOBAL,
                actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""),
                action="rule.reject",
                summary=f"ปฏิเสธกฎแบบเก่า (RandomForest) ทั้งหมด {result['rejected']} กฎ",
                details=result | {"reason": LEGACY_REJECT_REASON},
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return result


@router.post("/{rule_id}/reject")
async def reject_ml_rule(rule_id: str, req: RuleRejectRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Reject: platform admin, or Owner/Editor of the rule's origin."""
    checked, _role = _reviewable_rule(rule_id, current_user)
    try:
        with atomic():   # the rejection and its audit event commit together
            rule = rule_service.reject_rule(rule_id, rejected_by=current_user.get("username", "admin"), reason=req.reason)
            audit_log.write_audit_event(
                scope_id=_audit_scope(checked),
                actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""),
                action="rule.reject",
                summary=f"ปฏิเสธ ML rule: {rule_id}" + (f" ({req.reason})" if req.reason else ""),
                details={
                    "rule_id": rule_id,
                    "attack_type": rule.get("attack_type") if isinstance(rule, dict) else None,
                    "reason": req.reason,
                },
            )
        return {"message": "Rule rejected", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{rule_id}/revoke")
async def revoke_ml_rule(rule_id: str, req: RuleRevokeRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Take an approved rule out of the WAF (its ml-<id>.conf is removed, the row stays).

    Platform admin: any approved rule. Owner/Editor of the rule's origin: one
    deployed for that origin only. A rule written for every origin (no origin,
    or approved before rules were scoped) protects other tenants as well, so
    only the platform admin may take it away."""
    rule, role = _visible_rule(rule_id, current_user)
    is_admin = _is_admin(current_user)
    if rule.get("status") != "approved":
        raise HTTPException(status_code=400, detail=f"Only an approved rule can be revoked (status is {rule.get('status')})")
    if not is_admin and role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Owner or Editor of this origin required")
    if not _may_revoke(rule, is_admin, role):
        raise HTTPException(status_code=403,
                            detail="This rule runs for every origin; only the platform admin can revoke it")
    reason = (req.reason or "").strip()[:500]

    def _audit(action: str, r: dict, summary: str) -> None:
        audit_log.write_audit_event(
            scope_id=_audit_scope(rule),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action=action,
            summary=summary,
            details={
                "rule_id": rule_id,
                "attack_type": r.get("attack_type") if isinstance(r, dict) else None,
                "deployed_rule_id": r.get("deployed_rule_id") if isinstance(r, dict) else None,
                "deploy_scope": _deploy_scope(rule),
                "reason": reason,
            },
        )

    try:
        revoked = rule_service.revoke_rule(
            rule_id, revoked_by=current_user.get("username", "admin"), reason=reason,
            on_revoked=lambda r: _audit("rule.revoke", r, f"ยกเลิกการใช้งาน ML rule: {rule_id}"
                                        + (f" ({reason})" if reason else "")),
            on_remove_failed=lambda r, err: _audit(
                "rule.revoke_failed", r, f"ลบไฟล์กฎไม่สำเร็จ กฎยังทำงานอยู่: {rule_id} ({err})"),
            expected_origin_id=rule.get("origin_id") or "",
        )
        return {"message": "Rule revoked", "rule": _with_access(revoked, is_admin, role)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{rule_id}/backtest")
async def backtest_ml_rule(rule_id: str, days: int = rule_backtest.DEFAULT_DAYS,
                           current_user: dict = Depends(require_viewer_or_above)):
    """How many requests the WAF let through in the last `days` this rule would
    also have matched (services/rule_backtest.py). Read-only: nothing is
    deployed, and the result is stored on the rule for the review queue.

    Platform admin, or Owner/Editor of the rule's origin. A rule with an
    origin is replayed against that origin's own traffic only (it will only
    ever fire there), so a member never sees another tenant's requests; a
    global rule against everyone's, which is why it stays admin-only."""
    rule, _role = _reviewable_rule(rule_id, current_user)
    from api.ml import ML_SERVICE_URL, _ml_headers
    try:
        result = await rule_backtest.run_backtest(rule, _get_ch(), ML_SERVICE_URL, _ml_headers(), days)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:  # no traffic store to test against
        raise HTTPException(status_code=503, detail=str(e))
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {e}")
    rule_service.save_backtest(rule, result)
    return {"rule_id": rule_id, "backtest": result}


_ch = None


def _get_ch():
    """ClickHouse client, built on first backtest (constructing it connects and runs DDL)."""
    global _ch
    if _ch is None:
        from services.clickhouse_service import ClickHouseService
        _ch = ClickHouseService()
    return _ch


@router.delete("/{rule_id}")
async def delete_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    """Delete a rule (and its ml-<id>.conf when deployed). Platform admin only."""
    success = rule_service.delete_rule(rule_id)
    if success:
        return {"message": "Rule deleted"}
    raise HTTPException(status_code=404, detail="Rule not found")


def _scan_origin(origin_id: str, user: dict) -> dict:
    """The origin a single-origin CVE scan is for: the platform admin, or its
    Owner/Editor. 404 for a non-member or an archived/missing origin (as for
    its rules), 403 for a Viewer."""
    origin = _store.get_origin_by_id(origin_id)
    if not origin or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        raise HTTPException(status_code=404, detail="Origin not found")
    if _is_admin(user):
        return origin
    role = origin_role(origin, user.get("user_id"))
    if role is None:
        raise HTTPException(status_code=404, detail="Origin not found")
    if role not in REVIEW_ROLES:
        raise HTTPException(status_code=403, detail="Owner or Editor of this origin required")
    return origin


def _check_cve_scan_quota(origin_id: str) -> None:
    global _cve_scan_limiter
    if _cve_scan_limiter is None:
        from services.rate_limiter import RedisRateLimiter
        _cve_scan_limiter = RedisRateLimiter()
    # Fail closed like the analyst's quota (api/ml.py): no Redis, no scan.
    allowed, _, retry_after = _cve_scan_limiter.is_allowed(
        f"cve-scan:{origin_id}", CVE_SCAN_ORIGIN_LIMIT_PER_HOUR, 3600, fail_open=False
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"CVE scan limit reached for this origin ({CVE_SCAN_ORIGIN_LIMIT_PER_HOUR}/hour). Try again later.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post("/cve-scan")
async def run_cve_scan(
    days: Optional[int] = None,
    origin_id: Optional[str] = None,
    current_user: dict = Depends(require_viewer_or_above),
):
    """CVE Auto-Patch (2026-09-22). Admin-triggered, deliberately NOT a
    background worker -- this makes a real outbound call to NVD and can
    write into the live pending-rules queue; that stays an action someone
    chose to run and is watching, not something running unattended on a
    schedule. Proposals always land in the SAME queue ml-auto already
    writes to (created_by="cve-auto"), reviewed the same way, never
    auto-applied. "Proposal drafted" is the only claim made anywhere in
    this path -- protection starts when a human approves it.

    Without origin_id: every origin with tech stack tags, platform admin only.
    With origin_id (2026-10-27): that origin's tags only, for its Owner/Editor
    (or the admin), CVE_SCAN_ORIGIN_LIMIT_PER_HOUR per origin; the proposals
    are that origin's and the scan is recorded in its audit log.
    """
    window_days = days or CVE_SCAN_DEFAULT_WINDOW_DAYS
    scope_id = AUDIT_SCOPE_GLOBAL

    if origin_id:
        origin = _scan_origin(str(origin_id).strip(), current_user)
        if not origin.get("tech_stack_tags"):
            raise HTTPException(status_code=400,
                                detail="This origin has no tech stack tags yet; add them on the origin's page first")
        scope_id = str(origin["id"])
        _check_cve_scan_quota(scope_id)
        tagged_origins = [origin]
    else:
        if not _is_admin(current_user):
            raise HTTPException(status_code=403, detail="Admin access required to scan every origin")
        try:
            all_origins = rule_service.db.list_origins()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load origins: {e}")

        tagged_origins = [
            o for o in all_origins
            if o.get("status") not in ("archived", "deleted") and o.get("tech_stack_tags")
        ]
    keywords_searched, keywords_skipped = select_search_terms(tagged_origins)
    vulnerabilities = await fetch_recent_cves(keywords_searched, days=window_days)
    matches = match_cves_to_origins(vulnerabilities, tagged_origins)

    # Dedup against the FULL queue (any status) -- a CVE that was already
    # proposed and rejected should not come back on the next scan either.
    # 2026-10-26: per (CVE, origin). An approved CVE rule now runs for its
    # origin only and that origin's Owner/Editors review it, so a CVE matching
    # origins A and B needs a proposal for each: one origin's proposal (or its
    # rejection) must not leave the other unpatched. A rule that covers every
    # origin -- no origin_id, or approved before rules were scoped
    # (deploy_scope "global") -- still covers them all ("" below).
    try:
        existing_items = rule_service.list_rules()
    except Exception:
        existing_items = []
    already_proposed = {
        (i["cve_id"], "" if _deploy_scope(i) == "global" else str(i.get("origin_id") or ""))
        for i in existing_items if i.get("cve_id")
    }

    proposals_created = []
    to_create = []
    skipped_duplicate = 0
    skipped_no_valid_pattern = 0

    for match in matches:
        match_origin = str(match.get("origin_id") or "")
        if (match["cve_id"], "") in already_proposed or (match["cve_id"], match_origin) in already_proposed:
            skipped_duplicate += 1
            continue
        if len(to_create) >= CVE_SCAN_MAX_PROPOSALS:
            break

        pattern = await gemini_service.draft_cve_rule_pattern(
            match["cve_id"], match["description"], match["matched_tag"],
        )
        if not pattern:
            skipped_no_valid_pattern += 1
            continue
        try:
            re.compile(pattern)
        except re.error:
            # An LLM-drafted regex that doesn't even compile must never
            # reach the approval queue -- fail closed, skip this CVE.
            skipped_no_valid_pattern += 1
            continue

        # P4.2 (H57/H54): an operator keeps its backslashes (libmodsecurity
        # does not unescape them, so doubling made \s match a literal "\s");
        # one that cannot be quoted safely is skipped. The msg is escaped for
        # both its own single quotes and the action list's double quotes, and
        # control characters from the origin label are dropped.
        try:
            safe_pattern = escape_secrule_operator(pattern)
        except ValueError:
            skipped_no_valid_pattern += 1
            continue
        label = re.sub(r"[\x00-\x1f\x7f]", "", str(match.get("origin_label", "")))[:100]
        safe_msg = escape_secrule_message(f"CVE Auto-Patch: {match['cve_id']} (origin: {label})")
        secrule_template = (
            f"SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS \"@rx {safe_pattern}\" \\\n"
            f"    \"id:{{RULE_ID}},\\\n"
            f"    phase:2,\\\n"
            f"    deny,\\\n"
            f"    status:403,\\\n"
            f"    severity:CRITICAL,\\\n"
            f"    log,\\\n"
            f"    msg:'{safe_msg}'\"\n"
        )
        severity = match["severity"] if match["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "HIGH"
        rule_data = {
            "pattern": f"@rx {pattern}",
            "variable": "REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS",
            "attack_type": f"CVE Virtual Patch ({match['cve_id']})",
            "severity": severity,
            "secrule_template": secrule_template,
            "source_url": f"https://nvd.nist.gov/vuln/detail/{match['cve_id']}",
            "source_method": "GET",
            "cve_id": match["cve_id"],
            # match_cves_to_origins() matched this CVE's keywords against
            # this specific origin's tech_stack_tags, so the attribution is
            # exact rather than inferred.
            "origin_id": match.get("origin_id", ""),
            "origin_label": match.get("origin_label", ""),
        }
        to_create.append(rule_data)
        already_proposed.add((match["cve_id"], match_origin))

    # Every external call (NVD, Gemini) is done by now: the proposals and the
    # scan's audit event go in one short transaction with no I/O inside it.
    with atomic():
        for rule_data in to_create:
            proposals_created.append(rule_service.create_pending_rule(rule_data, created_by="cve-auto"))
        audit_log.write_audit_event(
            scope_id=scope_id,
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="cve_scan.run",
            summary=f"สแกน CVE feed: พบ {len(matches)} match, สร้าง proposal {len(proposals_created)} รายการ",
            details={
                "window_days": window_days,
                "cves_scanned": len(vulnerabilities),
                "keywords_searched": keywords_searched,
                "keywords_skipped": keywords_skipped,
                "matches_found": len(matches),
                "proposals_created": len(proposals_created),
                "skipped_duplicate": skipped_duplicate,
                "skipped_no_valid_pattern": skipped_no_valid_pattern,
            },
        )

    return {
        "status": "success",
        "origin_id": "" if scope_id == AUDIT_SCOPE_GLOBAL else scope_id,
        "cves_scanned": len(vulnerabilities),
        "keywords_searched": keywords_searched,
        "keywords_skipped": keywords_skipped,
        "matches_found": len(matches),
        "proposals_created": len(proposals_created),
        "skipped_duplicate": skipped_duplicate,
        "skipped_no_valid_pattern": skipped_no_valid_pattern,
        "proposals": proposals_created,
    }
