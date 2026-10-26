"""
Per-origin proposal lifecycle on the real tables: pending -> approved |
rejected, approved -> rolled_back. approve()/rollback() are the only paths
that change origins.anomaly_threshold, each pushes the host map to the WAF,
and a failed WAF reload leaves the origin unchanged.
"""
import pytest

from services.threshold_proposal_service import ThresholdProposalStore
from tests.helpers.seed import seed_origin, uid


class _WAF:
    def __init__(self):
        self.calls = 0
        self.fail = False

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("nginx -t failed")


@pytest.fixture
def waf():
    return _WAF()


@pytest.fixture
def store(db, waf):
    seed_origin(db, {"id": "o-tune", "status": "active"})
    return ThresholdProposalStore(apply_waf=waf)


def _proposal(store, proposed=7, current=5):
    return store.create({
        "origin_id": uid("o-tune"), "current_threshold": current, "proposed_threshold": proposed,
        "lookback_hours": 24, "reason": "test", "evidence": {"hosts": []},
    }, created_by="owner")


def _live(store):
    return store.db.get_origin_by_id(uid("o-tune")).get("anomaly_threshold")


def test_create_stores_a_pending_proposal_for_the_origin(store):
    p = _proposal(store)
    assert p["status"] == "pending"
    assert p["origin_id"] == uid("o-tune")


def test_create_without_an_origin_is_refused(store):
    with pytest.raises(ValueError):
        store.create({"current_threshold": 5, "proposed_threshold": 7, "lookback_hours": 24,
                      "reason": "x", "evidence": {}}, created_by="x")


def test_approve_sets_the_origins_threshold_and_pushes_the_waf(store, waf):
    p = _proposal(store)
    approved = store.approve(p["proposal_id"], approved_by="owner")
    assert approved["status"] == "approved"
    assert _live(store) == 7
    assert waf.calls == 1
    assert "previous_threshold" not in approved  # was on the platform threshold


def test_failed_waf_reload_leaves_the_origin_and_proposal_unchanged(store, waf):
    p = _proposal(store)
    waf.fail = True
    with pytest.raises(ValueError, match="could not be reloaded"):
        store.approve(p["proposal_id"], approved_by="owner")
    assert _live(store) is None
    assert store.get(p["proposal_id"])["status"] == "pending"


def test_reject_never_touches_the_origin_or_waf(store, waf):
    p = _proposal(store)
    assert store.reject(p["proposal_id"], rejected_by="owner", reason="no")["status"] == "rejected"
    assert _live(store) is None
    assert waf.calls == 0


def test_cannot_approve_twice_or_reject_a_decided_proposal(store):
    p = _proposal(store)
    store.approve(p["proposal_id"], approved_by="owner")
    with pytest.raises(ValueError):
        store.approve(p["proposal_id"], approved_by="owner")
    with pytest.raises(ValueError):
        store.reject(p["proposal_id"], rejected_by="owner")


def test_rollback_restores_the_platform_threshold(store):
    p = _proposal(store)
    store.approve(p["proposal_id"], approved_by="owner")
    assert store.rollback(p["proposal_id"], rolled_back_by="owner")["status"] == "rolled_back"
    assert _live(store) is None


def test_rollback_restores_the_origins_own_previous_value(store):
    first = _proposal(store, proposed=7)
    store.approve(first["proposal_id"], approved_by="owner")
    second = _proposal(store, current=7, proposed=9)
    approved = store.approve(second["proposal_id"], approved_by="owner")
    assert approved["previous_threshold"] == 7
    store.rollback(second["proposal_id"], rolled_back_by="owner")
    assert _live(store) == 7


def test_an_older_approval_cannot_be_rolled_back_over_a_newer_one(store):
    first = _proposal(store, proposed=7)
    store.approve(first["proposal_id"], approved_by="owner")
    second = _proposal(store, current=7, proposed=9)
    store.approve(second["proposal_id"], approved_by="owner")
    with pytest.raises(ValueError, match="later change"):
        store.rollback(first["proposal_id"], rolled_back_by="owner")
    assert _live(store) == 9


def test_cannot_rollback_a_pending_proposal_or_twice(store):
    p = _proposal(store)
    with pytest.raises(ValueError):
        store.rollback(p["proposal_id"], rolled_back_by="owner")
    store.approve(p["proposal_id"], approved_by="owner")
    store.rollback(p["proposal_id"], rolled_back_by="owner")
    with pytest.raises(ValueError):
        store.rollback(p["proposal_id"], rolled_back_by="owner")


def test_list_is_scoped_to_the_given_origins(store, db):
    seed_origin(db, {"id": "o-other", "status": "active"})
    mine = _proposal(store)
    store.create({"origin_id": uid("o-other"), "current_threshold": 5, "proposed_threshold": 7,
                  "lookback_hours": 24, "reason": "x", "evidence": {}}, created_by="x")
    assert [p["proposal_id"] for p in store.list(origin_ids=[uid("o-tune")])] == [mine["proposal_id"]]
    assert store.list(origin_ids=[]) == []
    assert len(store.list()) == 2
    assert store.list("approved", [uid("o-tune")]) == []
