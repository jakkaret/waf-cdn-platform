"""HTTP-level proof for the postmortem endpoints (2026-09-22): owner-only
auth (deliberate -- a postmortem merges in "global" scope audit events, see
api/ai_summary.py's module docstring for why), and that a Gemini failure
degrades gracefully instead of losing the timeline. build_incident_timeline
itself is proven separately in test_incident_postmortem_timeline.py."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import origins as origins_module
from api import ai_summary as ai_summary_module
import services.audit_log as audit_log_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(ai_summary_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _patch_dbs(monkeypatch, fake_infrastructure):
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())
    # Never touch real ClickHouse from these HTTP-level tests -- the
    # ClickHouse-connected path is already proven directly in
    # test_incident_postmortem_timeline.py.
    monkeypatch.setattr(ai_summary_module.ch, "connected", False)


@pytest.fixture()
def fake_narrative(monkeypatch):
    async def _fake(timeline):
        return {"narrative": "สรุปเหตุการณ์ทดสอบ", "degraded": False}
    monkeypatch.setattr(ai_summary_module.gemini_service, "generate_postmortem_narrative", _fake)


def _create_origin(client, token, auth_header, label="pm-origin"):
    resp = client.post(
        "/api/origins", json={"label": label, "ip": "203.0.113.77", "port": 8080},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def test_owner_can_create_list_and_get_a_postmortem(client, register_user, auth_header, fake_narrative):
    owner = register_user(email="pm-owner@example.com", username="pm_owner")
    owner_h = auth_header(owner["access_token"])
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/ai/postmortems/{origin_id}",
        json={"start_time": "2026-09-22 00:00:00", "end_time": "2026-09-22 06:00:00"},
        headers=owner_h,
    )
    assert resp.status_code == 200, resp.text
    created = resp.json()["postmortem"]
    assert created["ai_narrative"] == "สรุปเหตุการณ์ทดสอบ"
    pm_id = created["id"]

    resp = client.get(f"/api/ai/postmortems/{origin_id}", headers=owner_h)
    assert resp.status_code == 200, resp.text
    listed = resp.json()["postmortems"]
    assert any(p["id"] == pm_id for p in listed)

    resp = client.get(f"/api/ai/postmortems/{origin_id}/{pm_id}", headers=owner_h)
    assert resp.status_code == 200, resp.text
    assert resp.json()["postmortem"]["id"] == pm_id


def test_editor_viewer_and_stranger_cannot_create_a_postmortem(
    client, register_user, auth_header, fake_narrative,
):
    owner = register_user(email="pm-owner2@example.com", username="pm_owner2")
    editor = register_user(email="pm-editor2@example.com", username="pm_editor2")
    viewer = register_user(email="pm-viewer2@example.com", username="pm_viewer2")
    stranger = register_user(email="pm-stranger2@example.com", username="pm_stranger2")
    owner_h = auth_header(owner["access_token"])
    editor_h = auth_header(editor["access_token"])
    viewer_h = auth_header(viewer["access_token"])
    stranger_h = auth_header(stranger["access_token"])

    origin_id = _create_origin(client, owner["access_token"], auth_header)
    client.post(f"/api/origins/{origin_id}/editors", json={"email": "pm-editor2@example.com"}, headers=owner_h)
    client.post(f"/api/origins/{origin_id}/viewers", json={"email": "pm-viewer2@example.com"}, headers=owner_h)

    body = {"start_time": "2026-09-22 00:00:00", "end_time": "2026-09-22 06:00:00"}
    for h in (editor_h, viewer_h, stranger_h):
        resp = client.post(f"/api/ai/postmortems/{origin_id}", json=body, headers=h)
        assert resp.status_code == 403

    for h in (editor_h, viewer_h, stranger_h):
        resp = client.get(f"/api/ai/postmortems/{origin_id}", headers=h)
        assert resp.status_code == 403


def test_a_gemini_failure_still_persists_and_returns_the_timeline(
    client, register_user, auth_header, monkeypatch,
):
    async def _boom(timeline):
        raise RuntimeError("gemini is down")
    monkeypatch.setattr(ai_summary_module.gemini_service, "generate_postmortem_narrative", _boom)

    owner = register_user(email="pm-owner3@example.com", username="pm_owner3")
    owner_h = auth_header(owner["access_token"])
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/ai/postmortems/{origin_id}",
        json={"start_time": "2026-09-22 00:00:00", "end_time": "2026-09-22 06:00:00"},
        headers=owner_h,
    )
    assert resp.status_code == 200, resp.text
    postmortem = resp.json()["postmortem"]
    assert postmortem["ai_narrative"] is None
    assert postmortem["start_time"] == "2026-09-22 00:00:00"


def test_start_after_end_is_rejected(client, register_user, auth_header, fake_narrative):
    owner = register_user(email="pm-owner4@example.com", username="pm_owner4")
    owner_h = auth_header(owner["access_token"])
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/ai/postmortems/{origin_id}",
        json={"start_time": "2026-09-22 06:00:00", "end_time": "2026-09-22 00:00:00"},
        headers=owner_h,
    )
    assert resp.status_code == 422
