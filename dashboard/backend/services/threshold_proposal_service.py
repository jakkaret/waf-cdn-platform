"""
Per-origin anomaly-threshold tuning proposals (2026-10-27).

Each proposal belongs to one origin and is decided by that origin's Owner
only; platform admins take no part (see api/threshold_proposals.py). The
evidence is that origin's own traffic, and an approved value is stored on
the origin (origins.anomaly_threshold) and written into that origin's
host-map rule by services/managed_ruleset.render_hostmap, which sets
tx.inbound_anomaly_score_threshold in phase 1 for that origin's domains
only. Every other origin keeps the platform threshold from System settings
(or its own value), so one Owner's decision never loosens anyone else's
protection.

Never applies anything on its own: generate_origin_threshold_proposal()
only reads and decides, and only ThresholdProposalStore.approve() /
rollback() change an origin's threshold, after an explicit Owner action.

Before 2026-10-27 proposals tuned the single global threshold and needed
corroboration from several origins; those rows (origin_id NULL) are kept
for history and are no longer listed or actionable.
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# The origin needs at least this many requests in the lookback window
# before its block rate means anything.
MIN_SAMPLES = 200

# A block rate at or above this percentage suggests false positives and
# triggers a proposal.
BLOCK_RATE_TRIGGER_PCT = 15.0

# A proposal never moves the threshold by more than this in one step.
MAX_STEP_INCREASE = 2

# Hard bounds (also a CHECK on origins.anomaly_threshold): never above the
# stock CRS default, never below a floor that makes blocking meaningless.
CRS_DEFAULT_THRESHOLD = 10
MIN_THRESHOLD_FLOOR = 3

LOOKBACK_HOURS_DEFAULT = 24

_HOST_OK = re.compile(r"^[a-z0-9.-]{1,253}$")


def effective_threshold(origin: Dict[str, Any], platform_threshold: int) -> int:
    """The threshold the WAF applies to this origin's domains."""
    value = origin.get("anomaly_threshold")
    return int(value) if value is not None else int(platform_threshold)


def _query_block_rate(ch, hosts: List[str], lookback_hours: int) -> Optional[Tuple[int, int]]:
    if not getattr(ch, "connected", False):
        return None
    host_list = ", ".join(f"'{h}'" for h in hosts)  # hosts match _HOST_OK: no quotes possible
    query = f"""
        SELECT count() AS total, countIf(status_code IN (403, 429)) AS blocked
        FROM access_logs
        WHERE timestamp > now() - INTERVAL {int(lookback_hours)} HOUR
          AND host IN ({host_list})
    """
    try:
        rows = ch.query_stats(query)
    except Exception as e:  # fail closed: no evidence, no proposal
        logger.warning("Threshold proposal: ClickHouse query failed: %s", e)
        return None
    if not rows:
        return None
    total, blocked = rows[0]
    return int(total or 0), int(blocked or 0)


def generate_origin_threshold_proposal(
    ch,
    origin_id: str,
    hosts: List[str],
    current_threshold: int,
    lookback_hours: int = LOOKBACK_HOURS_DEFAULT,
) -> Tuple[Optional[Dict[str, Any]], str]:
    """(proposal, "") or (None, why there is nothing to propose).

    Reads only; the caller persists a returned proposal as pending."""
    hosts = sorted({h for h in (str(x).strip().lower().rstrip(".") for x in hosts) if _HOST_OK.match(h)})
    if not hosts:
        return None, "This origin has no verified domain, so there is no traffic to analyse."
    if current_threshold >= CRS_DEFAULT_THRESHOLD:
        return None, f"The threshold is already {current_threshold}, the CRS default and the highest this tuning goes."

    counts = _query_block_rate(ch, hosts, lookback_hours)
    if counts is None:
        return None, "Traffic logs are unavailable right now; try again later."
    total, blocked = counts
    if total < MIN_SAMPLES:
        return None, (f"Only {total} requests in the last {lookback_hours}h; "
                      f"at least {MIN_SAMPLES} are needed for a reliable block rate.")
    pct = round(blocked / total * 100, 1)
    if pct < BLOCK_RATE_TRIGGER_PCT:
        return None, (f"Block rate is {pct}% over the last {lookback_hours}h, below the "
                      f"{BLOCK_RATE_TRIGGER_PCT}% that suggests false positives. No change needed.")

    proposed = max(min(current_threshold + MAX_STEP_INCREASE, CRS_DEFAULT_THRESHOLD), MIN_THRESHOLD_FLOOR)
    return {
        "origin_id": origin_id,
        "current_threshold": current_threshold,
        "proposed_threshold": proposed,
        "lookback_hours": lookback_hours,
        "reason": (
            f"{blocked} of {total} requests ({pct}%) to {', '.join(hosts)} were blocked in the last "
            f"{lookback_hours}h, above the {BLOCK_RATE_TRIGGER_PCT}% trigger. Raising this origin's "
            f"inbound anomaly threshold from {current_threshold} to {proposed} should cut likely false "
            f"positives. It applies to this origin's domains only. A high block rate can also be a real "
            f"attack: check Traffic logs before approving."
        ),
        "evidence": {
            "hosts": hosts,
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate_pct": pct,
        },
    }, ""


def _default_apply_waf() -> None:
    """Rewrite the host map (which carries per-origin thresholds), nginx -t, reload."""
    from services import managed_ruleset
    from services.dynamodb_service import DynamoDBService
    from services.rule_manager import RuleManager
    managed_ruleset.apply(RuleManager(), DynamoDBService())


class ThresholdProposalStore:
    """Persistence + approval lifecycle: pending -> approved | rejected;
    approved -> rolled_back. create() only ever writes status="pending";
    approve() and rollback() are the only paths that change an origin's
    threshold, and both rewrite the WAF host map before recording the
    transition, undoing the change if the WAF reload fails."""

    def __init__(self, apply_waf: Optional[Callable[[], None]] = None):
        from services.dynamodb_service import DynamoDBService
        from services.pg_store import PgThresholdProposalRepository
        self.db = DynamoDBService()
        # waf.threshold_proposals. No I/O here: built at import time in
        # api/threshold_proposals.py.
        self._pg = PgThresholdProposalRepository()
        self._apply_waf = apply_waf or _default_apply_waf

    def create(self, proposal: Dict[str, Any], created_by: str) -> Dict[str, Any]:
        if not proposal.get("origin_id"):
            raise ValueError("A proposal belongs to an origin")
        return self._pg.create(proposal, created_by)

    def get(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        return self._pg.get(proposal_id)

    def list(self, status: Optional[str] = None, origin_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        return self._pg.list(status, origin_ids)

    def _change(self, origin_id: str, new: Optional[int], previous: Optional[int]) -> None:
        """Set the origin's threshold and push it to the WAF; on a failed
        reload put the old value back so the database matches the WAF."""
        if not self.db.update_origin(origin_id, {"anomaly_threshold": new}):
            raise ValueError("Origin not found")
        try:
            self._apply_waf()
        except Exception as e:
            logger.error("Threshold change for origin %s failed to apply: %s", origin_id, e)
            self.db.update_origin(origin_id, {"anomaly_threshold": previous})
            raise ValueError("The WAF could not be reloaded; the threshold was not changed") from e

    def _pending_or_approved(self, proposal_id: str, status: str) -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        if not proposal or not proposal.get("origin_id"):
            raise ValueError("Proposal not found")
        if proposal.get("status") != status:
            if status == "approved":
                raise ValueError(
                    f"Only an approved proposal can be rolled back (status is {proposal.get('status')})")
            raise ValueError(f"Proposal is already {proposal.get('status')}")
        return proposal

    def approve(self, proposal_id: str, approved_by: str) -> Dict[str, Any]:
        proposal = self._pending_or_approved(proposal_id, "pending")
        origin_id = proposal["origin_id"]
        # The origin's own value right now (None = platform threshold), not
        # the proposal's snapshot, so rollback restores what was really live.
        previous = (self.db.get_origin_by_id(origin_id) or {}).get("anomaly_threshold")
        self._change(origin_id, int(proposal["proposed_threshold"]), previous)

        updated = self._pg.transition(
            proposal_id, "pending",
            "status = 'approved', approved_by = %s, approved_at = now(), previous_threshold = %s",
            (approved_by, previous))
        if updated is None:
            # Decided by someone else meanwhile: undo the change.
            self._change(origin_id, previous, int(proposal["proposed_threshold"]))
            raise ValueError("Proposal is no longer pending")
        return updated

    def reject(self, proposal_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        self._pending_or_approved(proposal_id, "pending")
        updated = self._pg.transition(
            proposal_id, "pending",
            "status = 'rejected', rejected_by = %s, rejected_at = now(), reject_reason = %s",
            (rejected_by, reason))
        if updated is None:
            raise ValueError("Proposal is no longer pending")
        return updated

    def rollback(self, proposal_id: str, rolled_back_by: str) -> Dict[str, Any]:
        proposal = self._pending_or_approved(proposal_id, "approved")
        origin_id = proposal["origin_id"]
        live = (self.db.get_origin_by_id(origin_id) or {}).get("anomaly_threshold")
        if live != proposal["proposed_threshold"]:
            raise ValueError("A later change replaced this threshold; roll back the latest approved proposal instead")
        previous = proposal.get("previous_threshold")
        self._change(origin_id, previous, live)

        updated = self._pg.transition(
            proposal_id, "approved",
            "status = 'rolled_back', rolled_back_by = %s, rolled_back_at = now()", (rolled_back_by,))
        if updated is None:
            self._change(origin_id, live, previous)
            raise ValueError("Proposal is no longer approved")
        return updated
