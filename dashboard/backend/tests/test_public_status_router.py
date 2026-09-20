"""HTTP-level checks for the public, unauthenticated status endpoints.
Real network probing (api/cdn.py's _check_node against the real edge IPs) is
monkeypatched out here -- these tests are about the endpoint's auth-free
reachability and its response shape, not about live edge health, which
tests/test_public_status.py already covers at the service layer.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import public_status as public_status_api
import services.public_status as public_status_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(public_status_api.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _fake_probe(monkeypatch):
    async def fake_probe():
        return {
            "TH": {"online": True, "ip": "45.154.26.91", "status": "healthy"},
            "ASIA": {"online": True, "ip": "57.158.25.236", "status": "healthy"},
            "MAIN": {"online": True, "ip": "178.104.53.123", "status": "healthy"},
        }

    monkeypatch.setattr(public_status_module, "_probe_all_regions", fake_probe)
    public_status_module._SNAPSHOT_CACHE = None
    public_status_module._SNAPSHOT_AT = 0.0
    yield
    public_status_module._SNAPSHOT_CACHE = None
    public_status_module._SNAPSHOT_AT = 0.0


def test_public_status_is_reachable_with_no_auth_header_at_all(client):
    resp = client.get("/api/status/public")
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall_status"] == "operational"
    assert len(body["components"]) == 3


def test_public_status_response_never_contains_a_real_edge_ip(client):
    resp = client.get("/api/status/public")
    body_text = resp.text
    for ip in ("45.154.26.91", "57.158.25.236", "178.104.53.123"):
        assert ip not in body_text


def test_public_status_history_is_reachable_with_no_auth(client):
    # services/public_status.py's `db` singleton is patched to the fake
    # store by the autouse fixture in conftest.py, same as every other
    # module -- the real aggregation logic itself is covered in
    # tests/test_public_status.py.
    resp = client.get("/api/status/public/history?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert "th" in body and "asia" in body and "main" in body
