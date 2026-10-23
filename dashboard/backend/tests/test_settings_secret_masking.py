"""F-020: GET /api/settings never returns a raw secret, and the retired
global Telegram settings (bot token, chat id) are not served at all."""
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


def test_viewer_get_settings_never_contains_raw_secrets(client, register_user, auth_header, monkeypatch):
    fake = MagicMock()
    fake.get_settings.return_value = {
        "waf_mode": "blocking", "clickhouse_password": "pw-secret", "gemini_api_key": "k-secret",
    }
    monkeypatch.setattr(settings_module, "service", fake)
    h, _ = _viewer(register_user, auth_header)
    r = client.get("/api/settings/", headers=h)
    assert r.status_code == 200
    assert "pw-secret" not in r.text and "k-secret" not in r.text
    s = r.json()["settings"]
    assert s["clickhouse_password_set"] is True and s["gemini_api_key_set"] is True
    assert s["waf_mode"] == "blocking"


def test_admin_post_response_is_masked_too(client, register_user, auth_header, monkeypatch):
    fake = MagicMock()
    fake.get_settings.return_value = {"gemini_api_key": "k-secret"}
    fake.update_settings.return_value = {"gemini_api_key": "k-secret"}
    monkeypatch.setattr(settings_module, "service", fake)
    admin = register_user(email="adm2-mask@example.com", username="adm2_mask")
    r = client.post("/api/settings/", json={"waf_mode": "blocking"}, headers=auth_header(admin["access_token"]))
    assert r.status_code == 200
    assert "k-secret" not in r.text


def test_retired_telegram_settings_are_not_served_and_leave_the_file_on_save(tmp_path, monkeypatch):
    import services.settings_service as mod
    f = tmp_path / "system_settings.json"
    f.write_text(json.dumps({"telegram_bot_token": RAW, "telegram_chat_id": "42",
                             "telegram_notifications": True, "paranoia_level": 3}))
    monkeypatch.setattr(mod, "SETTINGS_FILE", f)
    monkeypatch.setattr(mod, "OVERRIDE_FILE", tmp_path / "ovr.conf")
    svc = mod.SettingsService.__new__(mod.SettingsService)
    svc.rule_manager = MagicMock()
    monkeypatch.setattr(mod.SettingsService, "_sync_ml_policy", lambda *a, **k: None)
    got = svc.get_settings()
    assert got["paranoia_level"] == 3
    assert not {"telegram_bot_token", "telegram_chat_id", "telegram_notifications"} & set(got)
    svc.update_settings({"paranoia_level": 2, "telegram_chat_id": "99"})
    saved = json.loads(f.read_text())
    assert saved["paranoia_level"] == 2 and RAW not in f.read_text()
    assert not {"telegram_bot_token", "telegram_chat_id", "telegram_notifications"} & set(saved)
