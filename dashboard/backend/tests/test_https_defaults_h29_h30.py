"""H29/H30: credentialed CORS origins and the Google redirect URI must be
https (localhost excepted for local development)."""
import pytest

import main
import services.auth_service as auth_mod


@pytest.mark.parametrize("origin,ok", [
    ("https://waf-it-kku.online", True),
    ("http://waf-it-kku.online", False),
    ("http://178.104.53.123:5173", False),
    ("http://localhost:5173", True),
])
def test_only_https_origins_may_use_credentials(origin, ok):
    assert main._credentialed_origin_ok(origin) is ok


def test_default_and_loaded_origins_are_https_or_local():
    assert all(main._credentialed_origin_ok(o) for o in main.ALLOWED_ORIGINS)


def test_google_flow_refuses_http_redirect(monkeypatch):
    monkeypatch.setattr(auth_mod, "GOOGLE_REDIRECT_URI", "http://example.com/api/auth/google/callback")
    with pytest.raises(RuntimeError):
        auth_mod.AuthService().start_google_flow()


def test_google_flow_accepts_https_redirect(monkeypatch):
    monkeypatch.setattr(auth_mod, "GOOGLE_REDIRECT_URI", "https://waf-it-kku.online/api/auth/google/callback")
    url, _ = auth_mod.AuthService().start_google_flow()
    assert "redirect_uri=https%3A%2F%2Fwaf-it-kku.online" in url
