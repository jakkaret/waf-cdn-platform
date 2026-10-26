"""Who may read the ML rules queue (GET /api/ml-rules/ and /{rule_id}).

2026-09-22: the queue had no per-tenant field at all, so listing/detail were
restricted to the platform admin -- any signed-up user could otherwise read
every tenant's real attack payloads/URLs (source_url values captured verbatim
from whatever request triggered the classifier).

2026-10-26: rows now carry origin_id, and an origin's members see that
origin's rules. What stays closed is pinned here: a user with no origin sees
nothing, a rule without an origin (the global queue) is the admin's only, and
a rule the caller may not see is a 404 -- not a 403 that would confirm it
exists. The per-origin cases are in test_ml_rules_origin_scope.py."""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.ml_rule_service as ml_rule_service_module
from services.rate_limiter import limiter
from api import auth as auth_module
from api import ml_rules as ml_rules_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ml_rules_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def service(monkeypatch):
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())
    svc = ml_rule_service_module.MLRuleService()
    monkeypatch.setattr(ml_rules_module, "rule_service", svc)
    return svc


def test_a_user_with_no_origin_sees_none_of_the_global_queue(client, register_user, auth_header, service):
    register_user(email="mlq-admin-decoy@example.com", username="mlq_admin_decoy")  # consumes first-user-admin slot
    viewer = register_user(email="mlq-viewer@example.com", username="mlq_viewer", role="viewer")
    service.create_pending_rule({"pattern": "@rx evil", "source_url": "/other-tenant?q=payload"})

    resp = client.get("/api/ml-rules/", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    assert resp.json() == {"rules": [], "is_admin": False}


def test_a_global_rules_detail_is_404_for_a_non_admin(client, register_user, auth_header, service):
    register_user(email="mlq-admin-decoy2@example.com", username="mlq_admin_decoy2")
    viewer = register_user(email="mlq-viewer2@example.com", username="mlq_viewer2", role="viewer")
    rule = service.create_pending_rule({"pattern": "@rx evil"})

    h = auth_header(viewer["access_token"])
    assert client.get(f"/api/ml-rules/{rule['rule_id']}", headers=h).status_code == 404
    assert client.get("/api/ml-rules/some-rule-id", headers=h).status_code == 404


def test_admin_can_still_list_and_read(client, register_user, auth_header, service):
    admin = register_user(email="mlq-admin3@example.com", username="mlq_admin3")  # first user -> admin
    rule = service.create_pending_rule({"pattern": "@rx evil"})

    resp = client.get("/api/ml-rules/", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["is_admin"] is True and [r["rule_id"] for r in resp.json()["rules"]] == [rule["rule_id"]]
    assert client.get(f"/api/ml-rules/{rule['rule_id']}", headers=auth_header(admin["access_token"])).status_code == 200


def test_signed_out_gets_401(client):
    assert client.get("/api/ml-rules/").status_code == 401
