"""
HTTP-level proof that cross-tenant threat intel sharing works end to end
through two real, separately-registered users -- not just at the service
layer (see tests/test_threat_intel.py for that). This is the "ลองเทสดูด้วย
ว่าทำงานได้จริงไหม ผ่านuserคนละคน" check: register user A and user B for
real via POST /api/auth/register, each with their own bearer token, opt
each in via the real PATCH endpoint, feed each one a pattern hit as if it
came from an attack on an origin they own, then read the trending feed
through the real GET endpoint and confirm it reports 2 distinct
contributors -- proving the shared aggregate crossed the tenant boundary
without leaking which two tenants they were.
"""
import datetime as dt

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import threat_intel as threat_intel_api_module
import services.threat_intel as threat_intel_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(threat_intel_api_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _opt_in(client: TestClient, headers: dict, enabled: bool = True):
    resp = client.patch("/api/threat-intel/opt-in", json={"enabled": enabled}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_two_different_registered_users_share_a_pattern_and_see_it_trend(
    client, register_user, auth_header,
):
    alice = register_user("alice@example.com", "alice")
    bob = register_user("bob@example.com", "bob")
    alice_headers = auth_header(alice["access_token"])
    bob_headers = auth_header(bob["access_token"])

    _opt_in(client, alice_headers, True)
    _opt_in(client, bob_headers, True)

    now = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)
    threat_intel_module.record_pattern_hit(alice["user"]["user_id"], "942100", "SQL Injection", now=now)
    threat_intel_module.record_pattern_hit(bob["user"]["user_id"], "942100", "SQL Injection", now=now)

    resp = client.get("/api/threat-intel/trending", headers=alice_headers)
    assert resp.status_code == 200, resp.text
    patterns = resp.json()["patterns"]
    assert len(patterns) == 1
    assert patterns[0]["rule_id"] == "942100"
    assert patterns[0]["distinct_tenants"] == 2
    assert patterns[0]["total_hits"] == 2

    # The response is the aggregate only -- neither user's identity, email,
    # or user_id ever appears in it.
    body_text = resp.text
    assert alice["user"]["user_id"] not in body_text
    assert bob["user"]["user_id"] not in body_text
    assert "alice@example.com" not in body_text
    assert "bob@example.com" not in body_text


def test_a_registered_user_who_never_opted_in_is_refused_the_feed(client, register_user, auth_header):
    dave = register_user("dave@example.com", "dave")
    dave_headers = auth_header(dave["access_token"])

    resp = client.get("/api/threat-intel/trending", headers=dave_headers)
    assert resp.status_code == 403


def test_the_opt_in_endpoint_actually_flips_the_flag_on_me(client, register_user, auth_header):
    erin = register_user("erin@example.com", "erin")
    erin_headers = auth_header(erin["access_token"])

    me_before = client.get("/api/auth/me", headers=erin_headers).json()
    assert me_before["share_threat_intel"] is False

    _opt_in(client, erin_headers, True)

    me_after = client.get("/api/auth/me", headers=erin_headers).json()
    assert me_after["share_threat_intel"] is True


def test_opting_back_out_immediately_blocks_the_feed_again(client, register_user, auth_header):
    frank = register_user("frank@example.com", "frank")
    frank_headers = auth_header(frank["access_token"])

    _opt_in(client, frank_headers, True)
    assert client.get("/api/threat-intel/trending", headers=frank_headers).status_code == 200

    _opt_in(client, frank_headers, False)
    assert client.get("/api/threat-intel/trending", headers=frank_headers).status_code == 403
