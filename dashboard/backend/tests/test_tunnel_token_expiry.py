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


def test_post_token_endpoint_actually_honors_a_long_expiry_not_just_the_response_field(
    client: TestClient, register_user, auth_header
):
    """The response has claimed "expires_in_days": 365 the whole time --
    this asserts the JWT itself matches that claim instead of trusting it."""
    admin = register_user(email="tt-admin1@example.com", username="tt_admin1")
    before = time.time()

    resp = client.post(
        "/api/tunnels/token",
        json={"domain": "unregistered-domain.example.com"},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["expires_in_days"] == 365

    exp = _decode_exp(body["token"])
    seconds_until_expiry = exp - before
    assert seconds_until_expiry > 300 * ONE_DAY, (
        f"token expires in {seconds_until_expiry / ONE_DAY:.1f} days -- "
        f"expected close to 365, got something matching the 60-minute login-session default instead"
    )


def test_post_token_endpoint_respects_a_caller_supplied_expires_days(
    client: TestClient, register_user, auth_header
):
    admin = register_user(email="tt-admin2@example.com", username="tt_admin2")
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


def test_config_generator_mints_a_long_lived_token_not_a_one_hour_session_token(
    client: TestClient, register_user, auth_header
):
    """This is the endpoint the 1-Click installer's copy-paste command
    actually calls -- the one that broke a real Lab deploy's tunnels ~1h
    after every fresh install before this fix."""
    admin = register_user(email="tt-admin3@example.com", username="tt_admin3")
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
    assert seconds_until_expiry > 300 * ONE_DAY, (
        f"config-generator's token expires in {seconds_until_expiry / ONE_DAY:.1f} days -- "
        f"a persistent Restart=always tunnel agent must not need re-installing every hour"
    )
