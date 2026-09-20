"""HTTP-level check that GET /api/onboarding/status wires the pure
compute_onboarding_status() logic to a real registered user's real origins,
end to end, through the actual endpoints the wizard itself calls."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import origins as origins_module
from api import domains as domains_module
from api import onboarding as onboarding_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    test_app.include_router(onboarding_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_a_fresh_user_is_told_to_create_an_origin_first(client, register_user, auth_header):
    user = register_user(email="wiz-fresh@example.com", username="wiz_fresh")
    resp = client.get("/api/onboarding/status", headers=auth_header(user["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["next_step"] == "create_origin"


def test_the_full_wizard_flow_reaches_done_through_real_endpoints(client, register_user, auth_header):
    user = register_user(email="wiz-full@example.com", username="wiz_full")
    headers = auth_header(user["access_token"])

    origin_resp = client.post("/api/origins", json={"label": "my-site", "ip": "203.0.113.9", "port": 3000}, headers=headers)
    assert origin_resp.status_code == 200, origin_resp.text
    origin_id = origin_resp.json()["id"]

    status1 = client.get("/api/onboarding/status", headers=headers).json()
    assert status1["next_step"] == "add_domain"

    domain_resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": "my-site.waf-it-kku.online"},  # own wildcard -> auto-verified
        headers=headers,
    )
    assert domain_resp.status_code == 200, domain_resp.text
    assert domain_resp.json()["auto_verified"] is True

    status2 = client.get("/api/onboarding/status", headers=headers).json()
    assert status2["next_step"] == "done"
    assert status2["onboarding_complete"] is True
