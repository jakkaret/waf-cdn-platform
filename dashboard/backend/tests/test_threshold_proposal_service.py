"""
T12 (docs/IMPLEMENTATION-ROADMAP.md, docs/PROJECT-DISCOVERY.md) -- self-tuning
anomaly-threshold proposal.

Written test-first against a design derived from two confirmed constraints:

1. The current WAF enforces exactly ONE global anomaly threshold via
   modsecurity/custom-rules/00-modsecurity-override.conf -- there is no
   per-origin threshold in this architecture (see
   test_settings_service_threshold_baseline.py). A proposal generator that
   pretends otherwise would be dishonest about what actually happens on
   approval.
2. Real per-"origin" block-rate data (queried live from ClickHouse,
   2026-09-05, using the same URL-pattern attribution `analytics.py` already
   uses elsewhere) shows real variance and a real noisy-small-sample origin:
   dvwa 8.5% (7,467 samples), juice 0.7% (3,192), vampi 21.3% (61 samples --
   too few to mean anything), "other"/unattributed 21.2% (378,689, mostly
   bot/scanner noise against the bare dashboard domain, not a real
   WAF-protected origin's traffic).

Because the enforcement is global but the evidence is per-origin, the
proposal generator's core safety job is: never let one noisy or actively
poisoned origin's traffic single-handedly justify a change that also
lowers protection for every OTHER origin sharing this WAF instance. Tests
below encode that as the central invariant.
"""
from services.threshold_proposal_service import (
    generate_threshold_proposal,
    MIN_SAMPLES_PER_ORIGIN,
    MIN_ORIGINS_FOR_CONSENSUS,
    BLOCK_RATE_TRIGGER_PCT,
    MAX_STEP_INCREASE,
    CRS_DEFAULT_THRESHOLD,
    MIN_THRESHOLD_FLOOR,
)


class _FakeCH:
    """Stands in for ClickHouseService: query_stats() returns pre-baked rows
    shaped like `SELECT origin, count(), countIf(blocked)` would."""

    def __init__(self, rows):
        self.connected = True
        self._rows = rows

    def query_stats(self, query):
        return self._rows


def _rows(*origin_total_blocked):
    """origin_total_blocked: sequence of (origin, total, blocked) tuples."""
    return [(o, t, b) for o, t, b in origin_total_blocked]


# ------------------------------------------------------------- no proposal

def test_no_proposal_when_no_origin_has_sufficient_samples():
    ch = _FakeCH(_rows(("dvwa", 5, 4), ("juice", 3, 3)))  # tiny samples, high rate
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal is None


def test_no_proposal_when_fewer_than_consensus_origins_have_sufficient_samples():
    """Only one origin (dvwa) clears MIN_SAMPLES_PER_ORIGIN; even though its
    block rate is elevated, MIN_ORIGINS_FOR_CONSENSUS requires corroboration
    from more than one origin before touching the shared global threshold.
    """
    assert MIN_ORIGINS_FOR_CONSENSUS >= 2
    ch = _FakeCH(_rows(
        ("dvwa", MIN_SAMPLES_PER_ORIGIN + 100, int((MIN_SAMPLES_PER_ORIGIN + 100) * 0.30)),
        ("vampi", 10, 8),  # far below the sample floor -- excluded from consensus
    ))
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal is None


def test_no_proposal_when_block_rate_is_below_trigger():
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.02)), ("juice", n, int(n * 0.03))))
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal is None


def test_no_proposal_when_only_one_sufficiently_sampled_origin_is_elevated():
    """CENTRAL SAFETY INVARIANT: one origin (dvwa) running hot while another
    well-sampled origin (juice) stays normal must NOT produce a proposal --
    a single origin (whether genuinely anomalous or actively feeding poisoned
    traffic to manipulate the recommendation) must not be able to change the
    shared global threshold that also governs every other origin's
    protection level.
    """
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(
        ("dvwa", n, int(n * 0.45)),   # way over trigger, alone
        ("juice", n, int(n * 0.02)),  # normal
    ))
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal is None, (
        "a proposal fired from a single hot origin corroborated by nothing -- "
        "this would let one origin's traffic (noisy or deliberately poisoned) "
        "change the shared global threshold for every other origin too"
    )


def test_no_proposal_when_already_at_the_crs_ceiling():
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.40)), ("juice", n, int(n * 0.35))))
    proposal = generate_threshold_proposal(ch, current_threshold=CRS_DEFAULT_THRESHOLD)
    assert proposal is None


# ---------------------------------------------------------------- proposal

def test_proposal_fires_when_multiple_origins_corroborate_elevated_block_rate():
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.40)), ("juice", n, int(n * 0.35))))
    proposal = generate_threshold_proposal(ch, current_threshold=5)

    assert proposal is not None
    assert proposal["current_threshold"] == 5
    assert proposal["proposed_threshold"] > 5
    assert "evidence" in proposal and len(proposal["evidence"]["origins"]) >= 2


def test_proposed_step_never_exceeds_max_step_increase():
    n = MIN_SAMPLES_PER_ORIGIN + 500
    # Even a wildly elevated rate must not jump the threshold by more than
    # MAX_STEP_INCREASE in a single proposal.
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.90)), ("juice", n, int(n * 0.85))))
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal["proposed_threshold"] - 5 <= MAX_STEP_INCREASE


def test_proposed_threshold_is_clamped_to_the_crs_ceiling():
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.90)), ("juice", n, int(n * 0.85))))
    proposal = generate_threshold_proposal(ch, current_threshold=CRS_DEFAULT_THRESHOLD - 1)
    assert proposal["proposed_threshold"] <= CRS_DEFAULT_THRESHOLD


def test_evidence_reports_excluded_low_sample_origins_transparently():
    """Origins below the sample floor must still be SHOWN in the evidence
    (so a human reviewer can see e.g. "vampi: 61 samples, excluded") even
    though they don't count toward the decision -- silently dropping them
    would hide exactly the kind of noisy-small-sample signal a reviewer
    needs to see to trust the recommendation.
    """
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(
        ("dvwa", n, int(n * 0.40)),
        ("juice", n, int(n * 0.35)),
        ("vampi", 61, 13),
    ))
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    excluded = [o for o in proposal["evidence"]["origins"] if o.get("excluded_insufficient_data")]
    assert any(o["origin"] == "vampi" for o in excluded)


def test_proposal_never_lowers_below_the_minimum_floor():
    """A degenerate/adversarial config (current_threshold already below the
    floor, e.g. from a bad manual edit) must not let the generator propose
    going even lower -- the floor is a hard safety bound, not just a
    starting point."""
    n = MIN_SAMPLES_PER_ORIGIN + 500
    ch = _FakeCH(_rows(("dvwa", n, int(n * 0.02)), ("juice", n, int(n * 0.02))))
    proposal = generate_threshold_proposal(ch, current_threshold=MIN_THRESHOLD_FLOOR)
    # Block rate is low here, so no proposal at all is expected -- but even
    # if some future logic path considered lowering, it must never leave the floor.
    if proposal is not None:
        assert proposal["proposed_threshold"] >= MIN_THRESHOLD_FLOOR


# -------------------------------------------------------- ClickHouse offline

def test_disconnected_clickhouse_yields_no_proposal_not_a_crash():
    ch = _FakeCH([])
    ch.connected = False
    proposal = generate_threshold_proposal(ch, current_threshold=5)
    assert proposal is None
