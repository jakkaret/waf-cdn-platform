"""
Per-origin tuning proposal: the decision rule, from one origin's own traffic.
Fires only on enough samples and a block rate at or above the trigger, moves
at most MAX_STEP_INCREASE, never above the CRS default, and always says why
when there is nothing to propose.
"""
from services.threshold_proposal_service import (
    BLOCK_RATE_TRIGGER_PCT,
    CRS_DEFAULT_THRESHOLD,
    MAX_STEP_INCREASE,
    MIN_SAMPLES,
    effective_threshold,
    generate_origin_threshold_proposal,
)


class _FakeCH:
    def __init__(self, total=0, blocked=0, connected=True):
        self.connected = connected
        self.rows = [(total, blocked)]
        self.queries = []

    def query_stats(self, query):
        self.queries.append(query)
        return self.rows


HOSTS = ["shop.example.com", "www.shop.example.com"]


def gen(ch, current=5, hosts=HOSTS):
    return generate_origin_threshold_proposal(ch, "origin-1", hosts, current, lookback_hours=24)


def test_query_covers_only_this_origins_hosts():
    ch = _FakeCH(1000, 300)
    gen(ch)
    assert "host IN ('shop.example.com', 'www.shop.example.com')" in ch.queries[0]


def test_hosts_that_are_not_plain_hostnames_are_dropped():
    ch = _FakeCH(1000, 300)
    gen(ch, hosts=["shop.example.com", "x') OR 1=1 --"])
    assert "OR 1=1" not in ch.queries[0]


def test_no_domain_means_no_proposal():
    proposal, why = gen(_FakeCH(1000, 300), hosts=[])
    assert proposal is None and "no verified domain" in why


def test_too_few_requests_means_no_proposal():
    proposal, why = gen(_FakeCH(MIN_SAMPLES - 1, MIN_SAMPLES - 1))
    assert proposal is None and str(MIN_SAMPLES) in why


def test_block_rate_below_trigger_means_no_proposal():
    total = 1000
    blocked = int(total * (BLOCK_RATE_TRIGGER_PCT - 1) / 100)
    proposal, why = gen(_FakeCH(total, blocked))
    assert proposal is None and "No change needed" in why


def test_already_at_the_crs_default_means_no_proposal():
    proposal, why = gen(_FakeCH(1000, 900), current=CRS_DEFAULT_THRESHOLD)
    assert proposal is None and str(CRS_DEFAULT_THRESHOLD) in why


def test_disconnected_clickhouse_means_no_proposal_not_a_crash():
    proposal, why = gen(_FakeCH(connected=False))
    assert proposal is None and "unavailable" in why


def test_proposal_for_an_elevated_block_rate():
    proposal, why = gen(_FakeCH(1000, 300), current=5)
    assert why == ""
    assert proposal["origin_id"] == "origin-1"
    assert proposal["current_threshold"] == 5
    assert proposal["proposed_threshold"] == 5 + MAX_STEP_INCREASE
    assert proposal["evidence"] == {"hosts": HOSTS, "total_requests": 1000, "blocked_requests": 300, "block_rate_pct": 30.0}
    assert "this origin's domains only" in proposal["reason"]


def test_proposal_is_clamped_to_the_crs_default():
    proposal, _ = gen(_FakeCH(1000, 300), current=CRS_DEFAULT_THRESHOLD - 1)
    assert proposal["proposed_threshold"] == CRS_DEFAULT_THRESHOLD


def test_effective_threshold_prefers_the_origins_own_value():
    assert effective_threshold({"anomaly_threshold": 8}, 5) == 8
    assert effective_threshold({}, 5) == 5
