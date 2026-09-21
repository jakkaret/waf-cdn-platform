"""Proves ML rule approve/reject endpoints write real audit events
(2026-09-22, Team Workspace + audit-log instrumentation follow-up).

rule_service.approve_rule/reject_rule are mocked (never call the real
MLRuleService here -- it touches the real waf_pending_rules DynamoDB table
AND real RuleManager.write_ml_rule, which writes actual ModSecurity conf
files and triggers nginx reload; test_dynamic_rate_limiter.py established
this exact mocking pattern for the same module-level rule_service
singleton). This test only proves the audit_log wiring, not MLRuleService
itself (which is untouched by this change)."""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import ml_rules as ml_rules_module
import services.audit_log as audit_log_module


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


@pytest.fixture(autouse=True)
def _patch_audit_log_db(monkeypatch, fake_infrastructure):
    """Explicitly force the waf_audit_log backing list empty before building
    the fake db, instead of trusting that fake_infrastructure's own
    _STORE.clear() has already run by this point. Empirically, even with
    fake_infrastructure declared as an explicit dependency here (which
    should order it first), a real failing test proved rows from a PRIOR
    test in this file were still present at this point: two tests in a row
    that each expect 0/1 new events saw 1/2 instead. _table()'s
    _STORE.setdefault(name, []) returns whatever list already sits at that
    key, so any stale list must be replaced here directly rather than
    relying on _STORE.clear() having already emptied it."""
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())


@pytest.fixture()
def fake_rule_service(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(ml_rules_module, "rule_service", fake)
    return fake


def _admin(client, register_user, auth_header):
    admin = register_user(email="mlrules-admin@example.com", username="mlrules_admin")
    return auth_header(admin["access_token"])


def test_approving_a_rule_writes_a_real_audit_event(
    client, register_user, auth_header, fake_rule_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.approve_rule.return_value = {
        "rule_id": "rule-1", "attack_type": "SQLi", "deployed_rule_id": 990123,
    }

    resp = client.post("/api/ml-rules/rule-1/approve", headers=admin_h)
    assert resp.status_code == 200, resp.text

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    approve_events = [e for e in events if e["action"] == "rule.approve"]
    assert len(approve_events) == 1
    assert approve_events[0]["details"]["rule_id"] == "rule-1"
    assert approve_events[0]["details"]["attack_type"] == "SQLi"
    assert approve_events[0]["details"]["deployed_rule_id"] == 990123


def test_rejecting_a_rule_writes_a_real_audit_event_with_reason(
    client, register_user, auth_header, fake_rule_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.reject_rule.return_value = {
        "rule_id": "rule-2", "attack_type": "XSS",
    }

    resp = client.post(
        "/api/ml-rules/rule-2/reject", json={"reason": "false positive"}, headers=admin_h,
    )
    assert resp.status_code == 200, resp.text

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    reject_events = [e for e in events if e["action"] == "rule.reject"]
    assert len(reject_events) == 1
    assert reject_events[0]["details"]["rule_id"] == "rule-2"
    assert reject_events[0]["details"]["reason"] == "false positive"


def test_a_failed_approve_writes_no_audit_event(
    client, register_user, auth_header, fake_rule_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.approve_rule.side_effect = ValueError("Rule is already approved")

    resp = client.post("/api/ml-rules/rule-3/approve", headers=admin_h)
    assert resp.status_code == 400

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    assert not [e for e in events if e["action"] == "rule.approve"]
