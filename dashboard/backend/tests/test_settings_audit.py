"""Proves POST /api/settings writes a real audit event with a before/after
diff (2026-09-22, feeds AI Incident Postmortem's root-cause timeline --
this is the exact scenario the concept card's own worked example describes:
a paranoia_level change causing a false-positive spike).

settings_module.service is mocked: SettingsService reads/writes the REAL
production data/system_settings.json file and calls RuleManager (real
ModSecurity conf + nginx reload) -- never touch that from a test. This only
proves the audit_log wiring in api/settings.py, not SettingsService itself
(untouched by this change)."""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import settings as settings_module
import services.audit_log as audit_log_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(settings_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _patch_audit_log_db(monkeypatch, fake_infrastructure):
    """See test_ml_rules_audit.py's identical fixture for why the
    waf_audit_log backing list is force-reset here directly rather than
    trusting fake_infrastructure's own _STORE.clear() to have already run."""
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())


@pytest.fixture()
def fake_settings_service(monkeypatch):
    fake = MagicMock()
    monkeypatch.setattr(settings_module, "service", fake)
    return fake


def _admin(client, register_user, auth_header):
    admin = register_user(email="settings-admin@example.com", username="settings_admin")
    return auth_header(admin["access_token"])


def test_changing_paranoia_level_writes_an_audit_event_with_old_and_new_value(
    client, register_user, auth_header, fake_settings_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_settings_service.get_settings.return_value = {"paranoia_level": 1, "waf_mode": "blocking"}
    fake_settings_service.update_settings.return_value = {"paranoia_level": 3, "waf_mode": "blocking"}

    resp = client.post("/api/settings/", json={"paranoia_level": 3}, headers=admin_h)
    assert resp.status_code == 200, resp.text

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    update_events = [e for e in events if e["action"] == "settings.update"]
    assert len(update_events) == 1
    assert update_events[0]["details"]["paranoia_level"] == {"old": 1, "new": 3}


def test_an_unchanged_value_writes_no_audit_event(
    client, register_user, auth_header, fake_settings_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_settings_service.get_settings.return_value = {"paranoia_level": 1}
    fake_settings_service.update_settings.return_value = {"paranoia_level": 1}

    resp = client.post("/api/settings/", json={"paranoia_level": 1}, headers=admin_h)
    assert resp.status_code == 200, resp.text

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    assert not [e for e in events if e["action"] == "settings.update"]


def test_a_secret_field_change_is_recorded_without_the_real_value(
    client, register_user, auth_header, fake_settings_service,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_settings_service.get_settings.return_value = {"telegram_bot_token": "old-real-secret-value"}
    fake_settings_service.update_settings.return_value = {"telegram_bot_token": "new-real-secret-value"}

    resp = client.post(
        "/api/settings/", json={"telegram_bot_token": "new-real-secret-value"}, headers=admin_h,
    )
    assert resp.status_code == 200, resp.text

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    update_events = [e for e in events if e["action"] == "settings.update"]
    assert len(update_events) == 1
    detail = update_events[0]["details"]["telegram_bot_token"]
    assert "old-real-secret-value" not in str(detail)
    assert "new-real-secret-value" not in str(detail)
