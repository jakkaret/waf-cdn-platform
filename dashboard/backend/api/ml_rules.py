import re
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from services.ml_rule_service import MLRuleService
from services.rbac import require_admin
from services import audit_log
from services.cve_feed import fetch_recent_cves, match_cves_to_origins
from services.gemini_service import gemini_service
from services.rule_manager import escape_secrule_string

router = APIRouter(prefix="/api/ml-rules", tags=["ml-rules"])
rule_service = MLRuleService()
AUDIT_SCOPE_GLOBAL = "global"

# CVE Auto-Patch (2026-09-22). Hard cap, not a magic number buried in the
# loop: the pending-rules queue already has ~268 unreviewed items as of
# this writing, and a scan that dumps dozens more into it in one call makes
# the product worse, not better. Approval is the real bottleneck here, not
# proposal generation.
CVE_SCAN_MAX_PROPOSALS = 5
CVE_SCAN_DEFAULT_WINDOW_DAYS = 14

class RuleRejectRequest(BaseModel):
    reason: Optional[str] = ""

@router.get("/")
async def list_ml_rules(status: Optional[str] = None, current_user: dict = Depends(require_admin)):
    """Admin-only (2026-09-22, diagnosing-bugs skill applied to the tenant-
    isolation audit's open finding). This queue has no per-tenant field
    anywhere in its data model -- neither create_pending_rule()'s item
    shape nor either of its two real callers (api/ml.py's user-invoked
    predict_and_suggest, this file's own CVE-Auto-Patch scan) ever capture
    an origin_id or domain, unlike alerts (which had a recoverable Host
    header). Was previously require_viewer_or_above -- i.e. any signed-up
    user -- exposing every tenant's real attack payloads/URLs to every
    other tenant. Since real per-tenant scoping cannot be built without an
    upstream data-model change, this is restricted to admin-only, matching
    the policy already applied to approve/reject/delete on this exact
    queue."""
    try:
        rules = rule_service.list_rules(status)
        return {"rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{rule_id}")
async def get_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    """Admin-only -- see list_ml_rules above for why."""
    rule = rule_service.get_rule_detail(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.post("/{rule_id}/approve")
async def approve_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    try:
        rule = rule_service.approve_rule(rule_id, approved_by=current_user.get("username", "admin"))
        audit_log.write_audit_event(
            scope_id=AUDIT_SCOPE_GLOBAL,
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="rule.approve",
            summary=f"อนุมัติ+deploy ML rule: {rule_id}",
            details={
                "rule_id": rule_id,
                "attack_type": rule.get("attack_type") if isinstance(rule, dict) else None,
                "deployed_rule_id": rule.get("deployed_rule_id") if isinstance(rule, dict) else None,
            },
        )
        return {"message": "Rule approved and deployed", "rule": rule}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{rule_id}/reject")
async def reject_ml_rule(rule_id: str, req: RuleRejectRequest, current_user: dict = Depends(require_admin)):
    try:
        rule = rule_service.reject_rule(rule_id, rejected_by=current_user.get("username", "admin"), reason=req.reason)
        audit_log.write_audit_event(
            scope_id=AUDIT_SCOPE_GLOBAL,
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

@router.delete("/{rule_id}")
async def delete_ml_rule(rule_id: str, current_user: dict = Depends(require_admin)):
    success = rule_service.delete_rule(rule_id)
    if success:
        return {"message": "Rule deleted"}
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/cve-scan")
async def run_cve_scan(
    days: Optional[int] = None,
    current_user: dict = Depends(require_admin),
):
    """CVE Auto-Patch (2026-09-22). Admin-triggered, deliberately NOT a
    background worker -- this makes a real outbound call to NVD and can
    write into the live pending-rules queue; that stays an action someone
    chose to run and is watching, not something running unattended on a
    schedule. Proposals always land in the SAME queue ml-auto already
    writes to (created_by="cve-auto"), reviewed the same way, never
    auto-applied. "Proposal drafted" is the only claim made anywhere in
    this path -- protection starts when a human approves it.
    """
    window_days = days or CVE_SCAN_DEFAULT_WINDOW_DAYS
    vulnerabilities = await fetch_recent_cves(days=window_days)

    try:
        all_origins = rule_service.db.origins_table.scan().get("Items", [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load origins: {e}")

    tagged_origins = [
        o for o in all_origins
        if o.get("status") not in ("archived", "deleted") and o.get("tech_stack_tags")
    ]
    matches = match_cves_to_origins(vulnerabilities, tagged_origins)

    # Dedup against the FULL queue (any status) -- a CVE that was already
    # proposed and rejected should not come back on the next scan either.
    try:
        existing_items = rule_service.table.scan().get("Items", [])
    except Exception:
        existing_items = []
    already_proposed_cve_ids = {i.get("cve_id") for i in existing_items if i.get("cve_id")}

    proposals_created = []
    skipped_duplicate = 0
    skipped_no_valid_pattern = 0

    for match in matches:
        if match["cve_id"] in already_proposed_cve_ids:
            skipped_duplicate += 1
            continue
        if len(proposals_created) >= CVE_SCAN_MAX_PROPOSALS:
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

        safe_pattern = escape_secrule_string(pattern, '"')
        safe_msg = escape_secrule_string(
            f"CVE Auto-Patch: {match['cve_id']} (origin: {match['origin_label']})", "'",
        )
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
        }
        created = rule_service.create_pending_rule(rule_data, created_by="cve-auto")
        proposals_created.append(created)
        already_proposed_cve_ids.add(match["cve_id"])

    audit_log.write_audit_event(
        scope_id=AUDIT_SCOPE_GLOBAL,
        actor_user_id=current_user.get("user_id"),
        actor_username=current_user.get("username", ""),
        action="cve_scan.run",
        summary=f"สแกน CVE feed: พบ {len(matches)} match, สร้าง proposal {len(proposals_created)} รายการ",
        details={
            "window_days": window_days,
            "cves_scanned": len(vulnerabilities),
            "matches_found": len(matches),
            "proposals_created": len(proposals_created),
            "skipped_duplicate": skipped_duplicate,
            "skipped_no_valid_pattern": skipped_no_valid_pattern,
        },
    )

    return {
        "status": "success",
        "cves_scanned": len(vulnerabilities),
        "matches_found": len(matches),
        "proposals_created": len(proposals_created),
        "skipped_duplicate": skipped_duplicate,
        "skipped_no_valid_pattern": skipped_no_valid_pattern,
        "proposals": proposals_created,
    }
