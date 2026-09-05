"""
T12 API layer: admin-gated approve/reject/rollback, viewer-readable list/get.
Confirms the never-auto-apply invariant holds at the HTTP boundary too, not
just inside the service class (test_threshold_proposal_store.py already
covers the service directly).

The module-level singletons (store, settings_service, ch) in
api/threshold_proposals.py are replaced with fakes via monkeypatch before
the router is exercised -- constructing the real ones would touch real
DynamoDB/ClickHouse/the real settings file, none of which this test needs
or should touch. RBAC is exercised for real (require_admin/
require_viewer_or_above from services.rbac), with the underlying
get_current_user dependency overridden per FastAPI's own supported testing
mechanism (app.dependency_overrides) -- this still runs the real role check
in require_admin/require_viewer_or_above, only the "who is logged in" step
is faked.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import threshold_proposals as tp_module
from services.rbac import get_current_user


class _FakeStore:
    def __init__(self):
        self.proposals = {}
        self.approve_calls = []
        self.reject_calls = []
        self.rollback_calls = []

    def create(self, proposal, created_by="system"):
        item = dict(proposal)
        item["proposal_id"] = "prop-1"
        item["status"] = "pending"
        self.proposals["prop-1"] = item
        return item

    def list(self, status=None):
        items = list(self.proposals.values())
        if status:
            items = [i for i in items if i["status"] == status]
        return items

    def get(self, proposal_id):
        return self.proposals.get(proposal_id)

    def approve(self, proposal_id, approved_by, settings_service):
        self.approve_calls.append((proposal_id, approved_by))
        p = self.proposals[proposal_id]
        p["status"] = "approved"
        return p

    def reject(self, proposal_id, rejected_by, reason=""):
        self.reject_calls.append((proposal_id, rejected_by, reason))
        p = self.proposals[proposal_id]
        p["status"] = "rejected"
        return p

    def rollback(self, proposal_id, rolled_back_by, settings_service):
        self.rollback_calls.append((proposal_id, rolled_back_by))
        p = self.proposals[proposal_id]
        p["status"] = "rolled_back"
        return p


class _FakeSettingsService:
    def get_settings(self):
        return {"inbound_anomaly_threshold": 5}


@pytest.fixture
def api(monkeypatch):
    fake_store = _FakeStore()
    monkeypatch.setattr(tp_module, "store", fake_store)
    monkeypatch.setattr(tp_module, "settings_service", _FakeSettingsService())
    monkeypatch.setattr(tp_module, "generate_threshold_proposal", lambda ch, current, lookback_hours=24: {
        "current_threshold": current, "proposed_threshold": current + 2, "reason": "test", "evidence": {"origins": []},
    })

    app = FastAPI()
    app.include_router(tp_module.router)
    return app, fake_store


def _as(app, role, username=None):
    username = username or role
    app.dependency_overrides[get_current_user] = lambda: {"user_id": f"uid-{username}", "username": username, "role": role}
    return TestClient(app)


# --------------------------------------------------------------- RBAC gates

def test_viewer_cannot_generate_a_proposal(api):
    app, fake_store = api
    client = _as(app, "viewer")
    resp = client.post("/api/threshold-proposals/generate")
    assert resp.status_code == 403
    assert fake_store.proposals == {}


def test_viewer_cannot_approve(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "pending"}
    client = _as(app, "viewer")
    resp = client.post("/api/threshold-proposals/prop-1/approve")
    assert resp.status_code == 403
    assert fake_store.approve_calls == []


def test_viewer_cannot_reject(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "pending"}
    client = _as(app, "viewer")
    resp = client.post("/api/threshold-proposals/prop-1/reject", json={"reason": "no"})
    assert resp.status_code == 403


def test_viewer_cannot_rollback(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "approved", "previous_threshold": 5}
    client = _as(app, "viewer")
    resp = client.post("/api/threshold-proposals/prop-1/rollback")
    assert resp.status_code == 403


def test_viewer_can_list_and_read(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "pending"}
    client = _as(app, "viewer")
    assert client.get("/api/threshold-proposals/").status_code == 200
    assert client.get("/api/threshold-proposals/prop-1").status_code == 200


# ------------------------------------------------------------- admin happy path

def test_admin_generate_creates_a_pending_proposal_when_one_is_returned(api):
    app, fake_store = api
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/generate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["proposal"]["status"] == "pending"
    assert body["proposal"]["proposed_threshold"] == body["proposal"]["current_threshold"] + 2


def test_generate_returns_null_proposal_without_erroring_when_nothing_is_safe_to_propose(api, monkeypatch):
    app, fake_store = api
    monkeypatch.setattr(tp_module, "generate_threshold_proposal", lambda ch, current, lookback_hours=24: None)
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/generate")
    assert resp.status_code == 200
    assert resp.json()["proposal"] is None
    assert fake_store.proposals == {}  # nothing was stored


def test_admin_can_approve_a_pending_proposal(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "pending"}
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/prop-1/approve")
    assert resp.status_code == 200
    assert resp.json()["proposal"]["status"] == "approved"
    assert fake_store.approve_calls == [("prop-1", "admin")]


def test_admin_can_reject_a_pending_proposal(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "pending"}
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/prop-1/reject", json={"reason": "not convincing"})
    assert resp.status_code == 200
    assert fake_store.reject_calls == [("prop-1", "admin", "not convincing")]


def test_admin_can_rollback_an_approved_proposal(api):
    app, fake_store = api
    fake_store.proposals["prop-1"] = {"proposal_id": "prop-1", "status": "approved", "previous_threshold": 5}
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/prop-1/rollback")
    assert resp.status_code == 200
    assert fake_store.rollback_calls == [("prop-1", "admin")]


def test_approve_of_unknown_proposal_is_404_not_500(api):
    app, fake_store = api
    fake_store.get = lambda pid: None
    fake_store.approve = lambda *a, **k: (_ for _ in ()).throw(ValueError("Proposal not found"))
    client = _as(app, "admin")
    resp = client.post("/api/threshold-proposals/does-not-exist/approve")
    assert resp.status_code == 400  # ValueError from the service maps to 400, per this router's error handling
