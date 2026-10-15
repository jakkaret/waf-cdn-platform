"""
T12 -- persistence/lifecycle for threshold proposals: create (pending) ->
approve|reject -> (approved proposals can be rolled back). Mirrors the
existing ml_rule_service.py pending-rule lifecycle's shape (same verbs,
same admin-gated pattern) but with its own DynamoDB-shaped table, since a
threshold proposal isn't a WAF rule.

Central requirements under test, from the user's explicit T12 brief:
  - never auto-applies: only approve() calls into SettingsService
  - rollback/versioning: approve() must capture the PRE-existing threshold
    so a later rollback() can restore it, and the whole history stays
    inspectable via list()
  - only a pending proposal can be approved/rejected; only an approved one
    can be rolled back (no state-machine violations)
"""
import pytest

from services.threshold_proposal_service import ThresholdProposalStore


class _FakeSettingsService:
    def __init__(self, initial_threshold=5):
        self._settings = {"inbound_anomaly_threshold": initial_threshold}
        self.update_calls = []

    def get_settings(self):
        return dict(self._settings)

    def update_settings(self, new_settings):
        self.update_calls.append(dict(new_settings))
        self._settings.update(new_settings)
        return self.get_settings()


@pytest.fixture
def store():
    return ThresholdProposalStore()   # waf.threshold_proposals, emptied per test


@pytest.fixture
def settings_service():
    return _FakeSettingsService(initial_threshold=5)


def _sample_proposal():
    return {
        "current_threshold": 5,
        "proposed_threshold": 7,
        "lookback_hours": 24,   # always set by build_proposal(); NOT NULL in PostgreSQL
        "reason": "test reason",
        "evidence": {"origins": []},
    }


def test_create_stores_a_pending_proposal(store):
    created = store.create(_sample_proposal())
    assert created["status"] == "pending"
    assert created["proposed_threshold"] == 7
    assert "proposal_id" in created


def test_approve_applies_the_threshold_via_settings_service(store, settings_service):
    created = store.create(_sample_proposal())
    approved = store.approve(created["proposal_id"], approved_by="admin-1", settings_service=settings_service)

    assert approved["status"] == "approved"
    assert settings_service.get_settings()["inbound_anomaly_threshold"] == 7
    assert settings_service.update_calls == [{"inbound_anomaly_threshold": 7}]


def test_approve_records_the_previous_threshold_for_rollback(store, settings_service):
    created = store.create(_sample_proposal())
    approved = store.approve(created["proposal_id"], approved_by="admin-1", settings_service=settings_service)
    assert approved["previous_threshold"] == 5


def test_reject_never_touches_settings_service(store, settings_service):
    created = store.create(_sample_proposal())
    rejected = store.reject(created["proposal_id"], rejected_by="admin-1", reason="not convincing")

    assert rejected["status"] == "rejected"
    assert rejected["reject_reason"] == "not convincing"
    assert settings_service.update_calls == []


def test_cannot_approve_an_already_approved_proposal(store, settings_service):
    created = store.create(_sample_proposal())
    store.approve(created["proposal_id"], approved_by="admin-1", settings_service=settings_service)

    with pytest.raises(ValueError):
        store.approve(created["proposal_id"], approved_by="admin-2", settings_service=settings_service)


def test_cannot_reject_an_already_rejected_proposal(store):
    created = store.create(_sample_proposal())
    store.reject(created["proposal_id"], rejected_by="admin-1")

    with pytest.raises(ValueError):
        store.reject(created["proposal_id"], rejected_by="admin-2")


def test_rollback_restores_the_previous_threshold(store, settings_service):
    created = store.create(_sample_proposal())
    approved = store.approve(created["proposal_id"], approved_by="admin-1", settings_service=settings_service)
    assert settings_service.get_settings()["inbound_anomaly_threshold"] == 7

    rolled_back = store.rollback(approved["proposal_id"], rolled_back_by="admin-2", settings_service=settings_service)

    assert rolled_back["status"] == "rolled_back"
    assert settings_service.get_settings()["inbound_anomaly_threshold"] == 5
    assert settings_service.update_calls[-1] == {"inbound_anomaly_threshold": 5}


def test_cannot_rollback_a_proposal_that_was_never_approved(store, settings_service):
    created = store.create(_sample_proposal())
    with pytest.raises(ValueError):
        store.rollback(created["proposal_id"], rolled_back_by="admin-2", settings_service=settings_service)


def test_cannot_rollback_the_same_approval_twice(store, settings_service):
    created = store.create(_sample_proposal())
    approved = store.approve(created["proposal_id"], approved_by="admin-1", settings_service=settings_service)
    store.rollback(approved["proposal_id"], rolled_back_by="admin-2", settings_service=settings_service)

    with pytest.raises(ValueError):
        store.rollback(approved["proposal_id"], rolled_back_by="admin-3", settings_service=settings_service)


def test_list_returns_full_history_for_audit(store, settings_service):
    p1 = store.create(_sample_proposal())
    store.approve(p1["proposal_id"], approved_by="admin-1", settings_service=settings_service)
    p2 = store.create(_sample_proposal())
    store.reject(p2["proposal_id"], rejected_by="admin-1")

    history = store.list()
    statuses = {p["proposal_id"]: p["status"] for p in history}
    assert statuses[p1["proposal_id"]] == "approved"
    assert statuses[p2["proposal_id"]] == "rejected"


def test_list_can_filter_by_status(store, settings_service):
    p1 = store.create(_sample_proposal())
    store.approve(p1["proposal_id"], approved_by="admin-1", settings_service=settings_service)
    store.create(_sample_proposal())  # left pending

    pending_only = store.list(status="pending")
    assert len(pending_only) == 1
    assert pending_only[0]["status"] == "pending"
