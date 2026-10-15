"""
T12 -- self-tuning anomaly-threshold proposal.

Generates a human-reviewable proposal to adjust the WAF's global anomaly
score threshold, based on real per-origin block-rate evidence from
ClickHouse. Never applies anything itself -- see api/threshold_proposals.py
for the admin-gated approve/reject/rollback endpoints that call
SettingsService.update_settings() only after an explicit human decision.

Architectural constraint this module is built around (confirmed by reading
services/settings_service.py and nginx/templates/modsecurity.d/setup.conf.template):
the WAF enforces exactly ONE global anomaly threshold, included for every
origin behind this instance. There is no per-origin threshold mechanism to
target. Because evidence is naturally per-origin but the lever is global,
the central safety property here is refusing to let one origin's traffic
(noisy, small-sample, or actively poisoned) single-handedly justify a change
that also changes protection for every other origin sharing this WAF.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Origins with fewer than this many requests in the lookback window are
# excluded from the decision entirely (still shown in evidence for
# transparency) -- too small a sample to mean anything.
MIN_SAMPLES_PER_ORIGIN = 200

# At least this many *independently* sufficiently-sampled origins must show
# an elevated block rate before a proposal fires. This is the guard against
# a single origin (whether genuinely anomalous or deliberately feeding
# poisoned traffic to manipulate the recommendation) changing the shared
# global threshold on its own.
MIN_ORIGINS_FOR_CONSENSUS = 2

# A per-origin block rate at or above this percentage counts as "elevated"
# for consensus purposes; the proposal's headline number is still the
# blended rate across corroborating origins.
BLOCK_RATE_TRIGGER_PCT = 15.0

# A proposal never moves the threshold by more than this in one step --
# bounded, incremental change only, never a large jump from one proposal.
MAX_STEP_INCREASE = 2

# Hard bounds: never propose above the stock CRS default (this WAF only
# ever *raises* the threshold to reduce false positives, never disables
# meaningful anomaly detection) and never below a floor that would make
# blocking nearly meaningless.
CRS_DEFAULT_THRESHOLD = 10
MIN_THRESHOLD_FLOOR = 3

LOOKBACK_HOURS_DEFAULT = 24

# Groups traffic by the origin it actually belongs to. access_logs.host
# (added 2026-09-22) carries the real Host header, so rows that have one
# are grouped by the real domain. The URL-keyword buckets below are the
# pre-host fallback and only apply to older rows -- they lump every
# tenant running the same app into one bucket ('%.php%' -> 'dvwa'), which
# is exactly the attribution error the host column exists to remove.
#
# Consequence worth knowing: real hostnames produce more, smaller origin
# buckets than four app-category buckets did, so MIN_SAMPLES_PER_ORIGIN
# and MIN_ORIGINS_FOR_CONSENSUS now bite on real per-domain volume.
# Fewer proposals, each backed by evidence that is actually per-origin.
_ORIGIN_CASE_SQL = """
multiIf(
  host != '', host,
  url LIKE '%juice%' OR url LIKE '%rest%', 'juice',
  url LIKE '%dvwa%' OR url LIKE '%.php%', 'dvwa',
  url LIKE '%vampi%' OR url LIKE '%/api/v1/%', 'vampi',
  url LIKE '%bwapp%', 'bwapp',
  'other'
) AS origin
"""


def _query_per_origin_block_rates(ch, lookback_hours: int) -> List[tuple]:
    if not getattr(ch, "connected", False):
        return []
    query = f"""
        SELECT {_ORIGIN_CASE_SQL},
               count() as total,
               countIf(status_code IN (403, 429)) as blocked
        FROM access_logs
        WHERE timestamp > now() - INTERVAL {int(lookback_hours)} HOUR
        GROUP BY origin
    """
    try:
        return ch.query_stats(query)
    except Exception as e:  # fail closed: no evidence, no proposal
        logger.warning(f"Threshold proposal: ClickHouse query failed: {e}")
        return []


def generate_threshold_proposal(
    ch,
    current_threshold: int,
    lookback_hours: int = LOOKBACK_HOURS_DEFAULT,
) -> Optional[Dict[str, Any]]:
    """Returns a proposal dict, or None if there is nothing safe to propose.

    Never mutates any state -- purely a read-and-decide function. The
    caller (api/threshold_proposals.py) is responsible for persisting a
    returned proposal as "pending" and for the fact that only an explicit
    admin approval ever calls SettingsService.update_settings().
    """
    rows = _query_per_origin_block_rates(ch, lookback_hours)
    if not rows:
        return None

    origins_evidence = []
    sufficiently_sampled = []
    for origin, total, blocked in rows:
        total = int(total)
        blocked = int(blocked)
        pct = round((blocked / total) * 100, 1) if total else 0.0
        excluded = total < MIN_SAMPLES_PER_ORIGIN
        entry = {
            "origin": origin,
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate_pct": pct,
            "excluded_insufficient_data": excluded,
        }
        origins_evidence.append(entry)
        if not excluded:
            sufficiently_sampled.append(entry)

    if len(sufficiently_sampled) < MIN_ORIGINS_FOR_CONSENSUS:
        logger.info(
            f"Threshold proposal: only {len(sufficiently_sampled)} origin(s) have "
            f">= {MIN_SAMPLES_PER_ORIGIN} samples in the last {lookback_hours}h -- "
            f"insufficient data for a system-wide change, no proposal generated"
        )
        return None

    elevated = [o for o in sufficiently_sampled if o["block_rate_pct"] >= BLOCK_RATE_TRIGGER_PCT]
    if len(elevated) < MIN_ORIGINS_FOR_CONSENSUS:
        logger.info(
            f"Threshold proposal: only {len(elevated)} sufficiently-sampled origin(s) "
            f"show an elevated block rate -- refusing to let a single origin drive a "
            f"global change, no proposal generated"
        )
        return None

    if current_threshold >= CRS_DEFAULT_THRESHOLD:
        return None

    # Blended rate across the corroborating (elevated, sufficiently-sampled)
    # origins only -- excluded/non-elevated origins never pull this number.
    total_reqs = sum(o["total_requests"] for o in elevated)
    total_blocked = sum(o["blocked_requests"] for o in elevated)
    blended_pct = round((total_blocked / total_reqs) * 100, 1) if total_reqs else 0.0

    proposed_threshold = min(
        current_threshold + MAX_STEP_INCREASE,
        CRS_DEFAULT_THRESHOLD,
    )
    proposed_threshold = max(proposed_threshold, MIN_THRESHOLD_FLOOR)

    return {
        "current_threshold": current_threshold,
        "proposed_threshold": proposed_threshold,
        "lookback_hours": lookback_hours,
        "reason": (
            f"Block rate {blended_pct}% across {len(elevated)} corroborating origins "
            f"({', '.join(o['origin'] for o in elevated)}) exceeds the "
            f"{BLOCK_RATE_TRIGGER_PCT}% trigger over the last {lookback_hours}h. "
            f"Raising the global inbound anomaly threshold from {current_threshold} "
            f"to {proposed_threshold} is expected to reduce likely false positives. "
            f"This threshold is GLOBAL -- it will apply to every origin behind this "
            f"WAF instance, not only the ones cited as evidence above."
        ),
        "evidence": {
            "blended_block_rate_pct": blended_pct,
            "origins": origins_evidence,
            "corroborating_origins": [o["origin"] for o in elevated],
        },
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ThresholdProposalStore:
    """Persistence + approval lifecycle for threshold proposals: pending ->
    approved|rejected; an approved proposal can additionally be rolled_back.
    Mirrors ml_rule_service.py's pending-rule lifecycle shape, backed by its
    own table, waf.threshold_proposals (a threshold proposal isn't a WAF rule).

    Never applies anything on its own -- create() only ever writes
    status="pending". SettingsService.update_settings() is called exactly
    twice in this class: once inside approve() (the only path that can ever
    change the live threshold) and once inside rollback() (reverting to the
    value approve() itself recorded). Both require an explicit caller-
    supplied identity (approved_by / rolled_back_by) -- enforcing that is
    the API layer's job (require_admin), not this class's, but this class
    never invents a default identity if the caller omits one.
    """

    def __init__(self):
        from services.dynamodb_service import DynamoDBService
        from services.pg_store import PgThresholdProposalRepository
        self.db = DynamoDBService()
        # waf.threshold_proposals. No I/O here: built at import time in
        # api/threshold_proposals.py.
        self._pg = PgThresholdProposalRepository()

    def create(self, proposal: Dict[str, Any], created_by: str = "ml-auto") -> Dict[str, Any]:
        return self._pg.create(proposal, created_by)

    def get(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        return self._pg.get(proposal_id)

    def list(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._pg.list(status)

    def approve(self, proposal_id: str, approved_by: str, settings_service) -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal not found")
        if proposal.get("status") != "pending":
            raise ValueError(f"Proposal is already {proposal.get('status')}")

        # Capture the threshold as it stands right now -- NOT the proposal's
        # own stale "current_threshold" snapshot from generation time -- so
        # rollback restores whatever was actually live at approval time.
        previous_threshold = settings_service.get_settings().get("inbound_anomaly_threshold")

        settings_service.update_settings({"inbound_anomaly_threshold": proposal["proposed_threshold"]})

        updated = self._pg.transition(
            proposal_id, "pending",
            "status = 'approved', approved_by = %s, approved_at = now(), previous_threshold = %s",
            (approved_by, previous_threshold))
        if updated is None:
            # Approved/rejected by someone else meanwhile: undo the change.
            settings_service.update_settings({"inbound_anomaly_threshold": previous_threshold})
            raise ValueError("Proposal is no longer pending")
        return updated

    def reject(self, proposal_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal not found")
        if proposal.get("status") != "pending":
            raise ValueError(f"Proposal is already {proposal.get('status')}")
        updated = self._pg.transition(
            proposal_id, "pending",
            "status = 'rejected', rejected_by = %s, rejected_at = now(), reject_reason = %s",
            (rejected_by, reason))
        if updated is None:
            raise ValueError("Proposal is no longer pending")
        return updated

    def rollback(self, proposal_id: str, rolled_back_by: str, settings_service) -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        if not proposal:
            raise ValueError("Proposal not found")
        if proposal.get("status") != "approved":
            raise ValueError(
                f"Only an approved proposal can be rolled back (status is {proposal.get('status')})"
            )

        settings_service.update_settings({"inbound_anomaly_threshold": proposal["previous_threshold"]})

        updated = self._pg.transition(
            proposal_id, "approved",
            "status = 'rolled_back', rolled_back_by = %s, rolled_back_at = now()", (rolled_back_by,))
        if updated is None:
            raise ValueError("Proposal is no longer approved")
        return updated
