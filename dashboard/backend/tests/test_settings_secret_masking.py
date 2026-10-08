"""F-020: GET /api/settings must never return the raw telegram_bot_token."""
import json
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import auth as auth_module
from api import settings as settings_module
from services.rate_limiter import limiter

RAW = "123456789:AAFakeTokenForPytestOnly_abcdefghijk"


@pytest.fixture()
def app() -> FastAPI:
    a = FastAPI()
    a.state.limiter = limiter
    a.include_router(auth_module.router)
    a.include_router(settings_module.router)
    return a


@pytest.fixture()
def client(app):
    return TestClient(app)


def _viewer(register_user, auth_header):
    register_user(email="adm-mask@example.com", username="adm_mask")  # first user = admin
    v = register_user(email="v-mask@example.com", username="v_mask", role="viewer")
    return auth_header(v["access_token"]), v


def test_viewer_get_settings_never_contains_raw_token(client, register_user, auth_header, monkeypatch):
    fake = MagicMock()
    fake.get_settings.return_value = {
        "waf_mode": "blocking", "telegram_bot_token": RAW, "telegram_chat_id": "42",
        "clickhouse_password": "pw-secret", "gemini_api_key": "k-secret",
    }
    monkeypatch.setattr(settings_module, "service", fake)
    h, _ = _viewer(register_user, auth_header)
    r = client.get("/api/settings/", headers=h)
    assert r.status_code == 200
    body = r.text
    assert RAW not in body and "pw-secret" not in body and "k-secret" not in body
    s = r.json()["settings"]
    assert "telegram_bot_token" not in s
    assert s["telegram_bot_token_set"] is True
    assert s["telegram_bot_token_masked"] == f"{RAW[:4]}...{RAW[-4:]}"
    assert s["waf_mode"] == "blocking"


def test_unset_token_reports_not_set(client, register_user, auth_header, monkeypatch):
    fake = MagicMock()
    fake.get_settings.return_value = {"telegram_bot_token": ""}
    monkeypatch.setattr(settings_module, "service", fake)
    h, _ = _viewer(register_user, auth_header)
    s = client.get("/api/settings/", headers=h).json()["settings"]
    assert s["telegram_bot_token_set"] is False
    assert s["telegram_bot_token_masked"] == ""


def test_admin_post_response_is_masked_too(client, register_user, auth_header, monkeypatch):
    fake = MagicMock()
    fake.get_settings.return_value = {"telegram_bot_token": RAW}
    fake.update_settings.return_value = {"telegram_bot_token": RAW}
    monkeypatch.setattr(settings_module, "service", fake)
    admin = register_user(email="adm2-mask@example.com", username="adm2_mask")
    r = client.post("/api/settings/", json={"waf_mode": "blocking"}, headers=auth_header(admin["access_token"]))
    assert r.status_code == 200
    assert RAW not in r.text


def test_service_update_does_not_wipe_token_after_masking(tmp_path, monkeypatch):
    import services.settings_service as mod
    f = tmp_path / "system_settings.json"
    f.write_text(json.dumps({"telegram_bot_token": RAW}))
    monkeypatch.setattr(mod, "SETTINGS_FILE", f)
    monkeypatch.setattr(mod, "OVERRIDE_FILE", tmp_path / "ovr.conf")
    svc = mod.SettingsService.__new__(mod.SettingsService)
    svc.rule_manager = MagicMock()
    monkeypatch.setattr(mod.SettingsService, "_sync_ml_policy", lambda *a, **k: None)
    svc.update_settings({"paranoia_level": 2, "telegram_bot_token": "abcd...wxyz"})  # masked echo ignored
    assert json.loads(f.read_text())["telegram_bot_token"] == RAW
    assert svc.get_settings()["telegram_bot_token"] == RAW  # internal callers still get raw
