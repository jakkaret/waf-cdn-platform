"""
Per-origin tuning proposals at the HTTP boundary: only the origin's Owner can
generate, approve, reject or roll back; Editors and Viewers of the origin can
read; everyone else, platform admins included, gets 404. RBAC runs for real
(origin_role on a real origin with real members); only the logged-in user,
ClickHouse and the WAF reload are faked.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import threshold_proposals as tp_module
from services.rbac import get_current_user
from services.threshold_proposal_service import ThresholdProposalStore
from tests.helpers.seed import ensure_user, seed_domain, seed_origin, uid

OWNER, EDITOR, VIEWER, ADMIN, STRANGER = (uid(n) for n in ("t-owner", "t-editor", "t-viewer", "t-admin", "t-stranger"))


class _FakeCH:
    connected = True

    def query_stats(self, query):
        return [(1000, 300)]


class _Settings:
    def get_settings(self):
        return {"inbound_anomaly_threshold": 5}


@pytest.fixture
def api(db, monkeypatch):
    for u in (EDITOR, VIEWER, STRANGER):
        ensure_user(u)
    ensure_user(ADMIN, role="admin")
    seed_origin(db, {"id": "o-api", "status": "active", "admin_user_id": OWNER})
    seed_domain(db, {"id": "d-api", "origin_id": "o-api", "domain_name": "tune.example.com", "dns_verified": True})
    db.add_origin_editor(uid("o-api"), EDITOR)
    db.add_origin_viewer(uid("o-api"), VIEWER)
    waf_calls = []
    monkeypatch.setattr(tp_module, "store", ThresholdProposalStore(apply_waf=lambda: waf_calls.append(1)))
    monkeypatch.setattr(tp_module, "ch", _FakeCH())
    monkeypatch.setattr(tp_module, "settings_service", _Settings())
    monkeypatch.setattr(tp_module.audit_log, "write_audit_event", lambda **kw: None)
    app = FastAPI()
    app.include_router(tp_module.router)
    return app, waf_calls


def _as(app, user_id, role="viewer"):
    app.dependency_overrides[get_current_user] = lambda: {"user_id": user_id, "username": user_id[:8], "role": role}
    return TestClient(app)


def _generate(app):
    r = _as(app, OWNER).post(f"/api/threshold-proposals/generate?origin_id={uid('o-api')}")
    assert r.status_code == 200, r.text
    return r.json()["proposal"]


def test_owner_generates_from_the_origins_own_traffic(api):
    app, _ = api
    p = _generate(app)
    assert p["origin_id"] == uid("o-api")
    assert (p["current_threshold"], p["proposed_threshold"]) == (5, 7)
    assert p["evidence"]["hosts"] == ["tune.example.com"]
    assert p["can_review"] is True


def test_second_generate_while_one_is_pending_returns_the_reason(api):
    app, _ = api
    _generate(app)
    r = _as(app, OWNER).post(f"/api/threshold-proposals/generate?origin_id={uid('o-api')}").json()
    assert r["proposal"] is None and "pending" in r["message"]


@pytest.mark.parametrize("who,role,status", [
    (EDITOR, "viewer", 403), (VIEWER, "viewer", 403), (ADMIN, "admin", 404), (STRANGER, "viewer", 404),
])
def test_only_the_owner_can_generate(api, who, role, status):
    app, _ = api
    r = _as(app, who, role).post(f"/api/threshold-proposals/generate?origin_id={uid('o-api')}")
    assert r.status_code == status


@pytest.mark.parametrize("action", ["approve", "reject", "rollback"])
@pytest.mark.parametrize("who,role,status", [
    (EDITOR, "viewer", 403), (VIEWER, "viewer", 403), (ADMIN, "admin", 404), (STRANGER, "viewer", 404),
])
def test_only_the_owner_can_decide(api, action, who, role, status):
    app, waf_calls = api
    p = _generate(app)
    r = _as(app, who, role).post(f"/api/threshold-proposals/{p['proposal_id']}/{action}", json={})
    assert r.status_code == status
    assert waf_calls == []


def test_owner_approves_then_rolls_back(api, db):
    app, waf_calls = api
    p = _generate(app)
    owner = _as(app, OWNER)
    assert owner.get("/api/threshold-proposals/origins").json()["origins"][0]["effective_threshold"] == 5
    assert owner.post(f"/api/threshold-proposals/{p['proposal_id']}/approve").status_code == 200
    assert db.get_origin_by_id(uid("o-api"))["anomaly_threshold"] == 7
    origins = owner.get("/api/threshold-proposals/origins").json()["origins"]
    assert origins[0]["effective_threshold"] == 7
    assert owner.post(f"/api/threshold-proposals/{p['proposal_id']}/rollback").status_code == 200
    assert db.get_origin_by_id(uid("o-api")).get("anomaly_threshold") is None
    assert len(waf_calls) == 2


def test_owner_rejects(api, db):
    app, waf_calls = api
    p = _generate(app)
    r = _as(app, OWNER).post(f"/api/threshold-proposals/{p['proposal_id']}/reject", json={"reason": "real attack"})
    assert r.json()["proposal"]["status"] == "rejected"
    assert db.get_origin_by_id(uid("o-api")).get("anomaly_threshold") is None
    assert waf_calls == []


@pytest.mark.parametrize("who,can_review", [(OWNER, True), (EDITOR, False), (VIEWER, False)])
def test_members_read_with_their_access(api, who, can_review):
    app, _ = api
    p = _generate(app)
    client = _as(app, who)
    listed = client.get("/api/threshold-proposals/").json()["proposals"]
    assert [x["proposal_id"] for x in listed] == [p["proposal_id"]]
    assert listed[0]["can_review"] is can_review
    assert client.get(f"/api/threshold-proposals/{p['proposal_id']}").json()["can_review"] is can_review


@pytest.mark.parametrize("who,role", [(ADMIN, "admin"), (STRANGER, "viewer")])
def test_non_members_see_nothing(api, who, role):
    app, _ = api
    p = _generate(app)
    client = _as(app, who, role)
    assert client.get("/api/threshold-proposals/").json()["proposals"] == []
    assert client.get(f"/api/threshold-proposals/{p['proposal_id']}").status_code == 404
    assert client.get(f"/api/threshold-proposals/?origin_id={uid('o-api')}").status_code == 404
    assert client.get("/api/threshold-proposals/origins").json()["origins"] == []


def test_unknown_proposal_is_404(api):
    app, _ = api
    assert _as(app, OWNER).post("/api/threshold-proposals/not-a-uuid/approve").status_code == 404
