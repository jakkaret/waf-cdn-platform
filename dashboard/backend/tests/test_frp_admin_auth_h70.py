"""H70/H87: the frps dashboard API used to fall back to admin/admin1234, a
password published with the repository. Now there is no fallback: without
FRP_ADMIN_USER and FRP_ADMIN_PASS the API is not called at all."""
import asyncio
from pathlib import Path

import pytest

import api.tunnels as tunnels_module
import services.origin_service as origin_service

BACKEND = Path(__file__).resolve().parents[1]


class _NoHTTP:
    def __init__(self, *a, **kw):
        raise AssertionError("frps API must not be called without credentials")


@pytest.fixture
def no_frp_creds(monkeypatch):
    monkeypatch.delenv("FRP_ADMIN_USER", raising=False)
    monkeypatch.delenv("FRP_ADMIN_PASS", raising=False)
    monkeypatch.setattr(origin_service.httpx, "AsyncClient", _NoHTTP)
    monkeypatch.setattr(tunnels_module.httpx, "AsyncClient", _NoHTTP)
    monkeypatch.setattr(origin_service, "_LIVE_PROXIES_CACHE", None)
    tunnels_module._TUNNELS_CACHE.clear()


def test_no_guessable_default_in_source():
    for path in BACKEND.rglob("*.py"):
        if "tests" in path.parts or ".venv" in path.parts:
            continue
        assert "admin1234" not in path.read_text(encoding="utf-8", errors="ignore"), path


@pytest.mark.parametrize("user,password", [("", ""), ("admin", ""), ("", "secret")])
def test_auth_is_none_unless_both_are_set(monkeypatch, user, password):
    monkeypatch.setenv("FRP_ADMIN_USER", user)
    monkeypatch.setenv("FRP_ADMIN_PASS", password)
    assert origin_service.frp_admin_auth() is None


def test_auth_uses_configured_values(monkeypatch):
    monkeypatch.setenv("FRP_ADMIN_USER", "ops")
    monkeypatch.setenv("FRP_ADMIN_PASS", "s3cret")
    assert origin_service.frp_admin_auth() == ("ops", "s3cret")


def test_live_proxy_poll_skips_frps_without_credentials(no_frp_creds):
    assert asyncio.run(origin_service.get_live_proxies(force=True)) == []


def test_tunnels_status_reports_missing_credentials(no_frp_creds):
    user = {"user_id": "u-h70", "role": "admin", "username": "ops"}
    result = asyncio.run(tunnels_module.get_tunnels_status(scope="my", current_user=user))
    assert result["success"] is False
    assert "not configured" in result["error"]
    assert result["tunnels"] == []
