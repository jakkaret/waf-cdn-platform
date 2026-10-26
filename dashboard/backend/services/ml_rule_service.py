import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from services.dynamodb_service import DynamoDBService
from services.pg_store import PgPendingRuleRepository
from services.rule_manager import RuleManager

logger = logging.getLogger(__name__)

# Newest request examples kept on a pending rule (record_hit).
MAX_EXAMPLES = 5
# Approved ML/CVE rules one origin may have deployed (scoped to it). Same
# default as tenant rules (services/tenant_rules.MAX_RULES_PER_ORIGIN): every
# rule runs on the shared WAF, so one origin's Owner/Editors cannot grow the
# rule set without bound. Global rules (no origin) are not capped.
MAX_APPROVED_RULES_PER_ORIGIN = int(os.getenv("ML_RULES_PER_ORIGIN", "50"))


def _default_generator(created_by: str) -> str:
    """Generator of a rule stored before the field existed (or written without it)."""
    return "cve" if created_by == "cve-auto" else "rf-regex"


def _example(rule_data: Dict[str, Any], seen_at: str) -> Dict[str, Any]:
    example = {
        "url": str(rule_data.get("source_url", ""))[:200],
        "method": rule_data.get("source_method", "GET"),
        "seen_at": seen_at,
    }
    # H50: a proposal a signed-in user asked for (POST /api/ml/predict-and-
    # suggest, open to viewers) names that user, so the approval queue shows
    # who is behind each request instead of an anonymous "ml-auto".
    if rule_data.get("requested_by"):
        example["requested_by"] = str(rule_data["requested_by"])[:80]
        example["requested_by_id"] = str(rule_data.get("requested_by_id") or "")[:64]
    return example


def remove_deployed_rule_files(deployed_rule_ids: List[int]) -> None:
    """Remove ml-<id>.conf for approved rules whose origin was deleted
    (PgStore.hard_delete_origin returns their ids; call it after commit).
    Each removal is nginx -t + reload like any rule change; one that fails is
    logged and left for the admin (Security rules page), not retried."""
    if not deployed_rule_ids:
        return
    manager = RuleManager()
    for deployed_rule_id in deployed_rule_ids:
        try:
            manager.delete_rule(f"ml-{int(deployed_rule_id)}")
        except Exception:
            logger.exception("could not remove ml-%s.conf of a deleted origin", deployed_rule_id)


def with_defaults(item: Dict[str, Any]) -> Dict[str, Any]:
    """Fill the 2026-10-13 fields on rows written before they existed, so the API shape is stable."""
    item = dict(item)
    item.setdefault("generator", _default_generator(item.get("created_by", "")))
    item.setdefault("detector", "")
    item.setdefault("dedup_key", "")
    item["hit_count"] = int(item.get("hit_count") or 1)
    item.setdefault("examples", [])
    item.setdefault("last_seen_at", item.get("created_at", ""))
    return item


class MLRuleService:
    def __init__(self):
        self.db = DynamoDBService()
        self.rule_manager = RuleManager()
        # waf.pending_rules. No I/O here: api/ml_rules.py builds this at import.
        self._pg = PgPendingRuleRepository()

    def create_pending_rule(self, rule_data: Dict[str, Any], created_by: str = "ml-auto") -> Dict[str, Any]:
        """Save a new pending rule (a pending rule with the same dedup_key absorbs it)."""
        rule_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        item = {
            "rule_id": rule_id,
            "created_at": timestamp,
            "status": "pending",
            "pattern": rule_data.get("pattern", ""),
            "variable": rule_data.get("variable", "REQUEST_URI|REQUEST_BODY"),
            "attack_type": rule_data.get("attack_type", "Anomaly"),
            "severity": rule_data.get("severity", "CRITICAL"),
            "secrule_template": rule_data.get("secrule_template", ""),
            "source_url": rule_data.get("source_url", ""),
            "source_method": rule_data.get("source_method", "GET"),
            "created_by": created_by,
            # CVE Auto-Patch (2026-09-22): empty string for every other
            # created_by. Used for dedup -- a scan never proposes a second
            # rule for a CVE ID that already has one in the queue.
            "cve_id": rule_data.get("cve_id", ""),
            # 2026-09-23: which origin's exposure prompted this proposal.
            # The CVE scanner knows it exactly (cve_feed.match_cves_to_origins
            # matches a CVE's keywords against one origin's tech_stack_tags).
            # The ML analyst stores the origin its Owner/Editor picked
            # (api/ml.py predict_and_suggest), or "" when none was picked --
            # an empty value here means "not attributable", never "belongs
            # to everyone".
            #
            # 2026-10-26: the origin also decides who reviews the rule and
            # where it runs. A rule with an origin is shown to that origin's
            # members, may be approved by its Owner/Editors, and is deployed
            # scoped to that origin only (approve_rule). A rule without one
            # stays in the platform admin's queue and deploys globally.
            "origin_id": rule_data.get("origin_id", ""),
            "origin_label": rule_data.get("origin_label", ""),
            # 2026-10-13: which generator wrote the rule ("rf-regex" = the
            # RandomForest path's fixed regex / 40-char literal, "gen3-detector"
            # = a Gen 3 value detector, "cve" = CVE Auto-Patch) and the key
            # repeats merge on. hit_count / examples / last_seen_at grow when
            # the same proposal comes back (record_hit) instead of the queue
            # getting one near-identical row per flagged request.
            "generator": rule_data.get("generator") or _default_generator(created_by),
            "detector": rule_data.get("detector", ""),
            "dedup_key": rule_data.get("dedup_key", ""),
            "hit_count": 1,
            "examples": [_example(rule_data, timestamp)],
            "last_seen_at": timestamp,
        }

        return with_defaults(self._pg.create(item))

    def find_pending_by_dedup_key(self, dedup_key: str, origin_id: str = "") -> Optional[Dict[str, Any]]:
        """The pending rule a new proposal with this key should merge into, if
        any: only one of the same origin ("" = the global queue)."""
        found = self._pg.find_pending_by_dedup_key(dedup_key, origin_id)
        return with_defaults(found) if found else None

    def record_hit(self, rule: Dict[str, Any], rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add one more request behind an existing pending rule (count, last seen, newest examples)."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        updated = self._pg.record_hit(rule["rule_id"], _example(rule_data, timestamp), timestamp)
        return with_defaults(updated) if updated else rule

    def save_backtest(self, rule: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Keep the latest backtest on the rule so the queue shows it without re-running."""
        self._pg.save_backtest(rule["rule_id"], result)
        return {**rule, "backtest": result}

    def list_rules(self, status: str = None, origin_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """List rules (newest first), optionally filtered by status and, when
        origin_ids is given, to rules of those origins only."""
        try:
            return [with_defaults(i) for i in self._pg.list(status, origin_ids)]
        except Exception as e:
            print(f"Error fetching rules: {e}")
            return []

    def get_rule_detail(self, rule_id: str) -> Optional[Dict[str, Any]]:
        found = self._pg.get(rule_id)
        return with_defaults(found) if found else None

    def _max_rule_id_on_disk(self) -> int:
        """Highest numeric id among the rule files (0 when none)."""
        ids = []
        for r in self.rule_manager.list_rules():
            try:
                ids.append(int(r["id"].replace("custom-", "").replace("ml-", "")))
            except ValueError:
                continue
        return max(ids) if ids else 0

    def approve_rule(self, rule_id: str, approved_by: str, on_approved=None,
                     on_deploy_failed=None, expected_origin_id: Optional[str] = None) -> Dict[str, Any]:
        """Approve and deploy a pending rule, in three steps (nothing slow
        inside the transaction):
        1. one short transaction: lock, allocate the next ModSecurity id
           above both the files on disk and every id ever recorded (a deleted
           ml-<id>.conf must not hand out a used id again), mark approved and
           call on_approved(rule) -- the audit event -- so both commit together;
        2. after commit: write ml-<id>.conf and reload nginx;
        3. if step 2 fails: a compensating transaction puts the rule back to
           pending and calls on_deploy_failed(rule, error) (the approve event
           cannot be deleted: audit_logs is append-only), removes a file it
           wrote, then re-raises.

        Where the rule runs comes from the locked row, not from the caller: a
        rule with an origin_id is written scoped to that origin
        (rule_manager.scope_ml_rule_to_origin), whoever approves it; one
        without stays global. expected_origin_id is the origin the caller was
        authorised for ("" = global); the row must still have it.
        """
        from db import pool
        with pool.transaction():
            rule = self._pg.reserve_approval(rule_id, approved_by, self._max_rule_id_on_disk(),
                                             expected_origin_id=expected_origin_id,
                                             max_per_origin=MAX_APPROVED_RULES_PER_ORIGIN)
            if on_approved:
                on_approved(rule)
        modsec_rule_id = rule["deployed_rule_id"]
        try:
            secrule_code = rule["secrule_template"].replace("{RULE_ID}", str(modsec_rule_id))
            self.rule_manager.write_ml_rule(modsec_rule_id, secrule_code, origin_id=rule.get("origin_id") or "")
        except Exception as exc:
            try:
                with pool.transaction():
                    self._pg.undo_approval(rule_id, modsec_rule_id)
                    if on_deploy_failed:
                        on_deploy_failed(rule, exc)
            finally:
                try:
                    self.rule_manager.delete_rule(f"ml-{modsec_rule_id}")
                except Exception:
                    pass
            raise
        return with_defaults(rule)

    def revoke_rule(self, rule_id: str, revoked_by: str, reason: str = "", on_revoked=None,
                    on_remove_failed=None, expected_origin_id: Optional[str] = None) -> Dict[str, Any]:
        """Take an approved rule out of the WAF, approve_rule in reverse:
        1. one short transaction: lock, mark revoked and call on_revoked(rule)
           -- the audit event -- so both commit together;
        2. after commit: remove ml-<id>.conf (nginx -t + reload; delete_rule
           puts the file back if nginx refuses the config). A file already
           gone is fine: the rule is not running either way;
        3. if step 2 fails: a compensating transaction puts the rule back to
           approved (it is still running) and calls on_remove_failed(rule,
           error), then re-raises.
        The row and its deployed_rule_id stay, so the id is never reused."""
        from db import pool
        with pool.transaction():
            rule = self._pg.reserve_revoke(rule_id, revoked_by, reason, expected_origin_id=expected_origin_id)
            if on_revoked:
                on_revoked(rule)
        try:
            self.rule_manager.delete_rule(f"ml-{int(rule['deployed_rule_id'])}")
        except Exception as exc:
            with pool.transaction():
                self._pg.undo_revoke(rule_id)
                if on_remove_failed:
                    on_remove_failed(rule, exc)
            raise
        return with_defaults(rule)

    def reject_rule(self, rule_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        return with_defaults(self._pg.reject(rule_id, rejected_by, reason))

    def reject_legacy_pending(self, rejected_by: str, reason: str) -> Dict[str, int]:
        """Reject every pending rule written by the retired RandomForest path ("rf-regex").

        2026-10-13: proposals come from Gen 3 only, and the RF rules left in the queue
        only ever matched the request they came from. Gen3-detector and CVE rules are
        left alone; a rule an admin approved meanwhile is no longer pending and is skipped.
        """
        return self._pg.reject_legacy(rejected_by, reason)

    def delete_rule(self, rule_id: str) -> bool:
        rule = self.get_rule_detail(rule_id)
        if not rule:
            return False
        # An approved, deployed rule also loses its .conf file.
        if rule.get("status") == "approved" and rule.get("deployed_rule_id"):
            try:
                self.rule_manager.delete_rule(f"ml-{rule['deployed_rule_id']}")
            except Exception:
                pass
        self._pg.delete(rule_id)
        return True
