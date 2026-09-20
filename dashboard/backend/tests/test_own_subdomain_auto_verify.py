"""
Scenario: 2026-09-22 (self-service onboarding, overnight session) --
POST /api/origins/{id}/domains always wrote dns_verified: False, even when
the chosen domain is a subdomain of our own already-DNS-controlled wildcard
(*.waf-it-kku.online, confirmed live earlier this session to already
resolve to the edge with zero setup). That meant the "use our subdomain,
zero DNS work" onboarding path still made the user click through a CNAME/
TXT verification screen for a domain we already own -- exactly the
friction item 7 (self-service onboarding) in the roadmap flagged.

A single-label subdomain of WAF_OWN_WILDCARD_DOMAIN (default
waf-it-kku.online) is now auto-verified at creation, except the three
labels already aliased to the dashboard itself in the Caddyfile (www, main,
dash) and the bare apex -- claiming those would collide with the real
dashboard UI at that hostname. Everything else (external domains, and
multi-label names under our own domain) still goes through the normal
CNAME+TXT flow unchanged.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import origins as origins_module
from api import domains as domains_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _create_origin(client, token, auth_header, label="onboard-origin"):
    resp = client.post(
        "/api/origins", json={"label": label, "ip": "203.0.113.30", "port": 8080},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"] if "id" in resp.json() else resp.json()["origin_id"]


def test_a_single_label_subdomain_of_our_own_wildcard_is_auto_verified(client, register_user, auth_header):
    owner = register_user(email="wc-owner@example.com", username="wc_owner")
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": "myshop.waf-it-kku.online"},
        headers=auth_header(owner["access_token"]),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["domain"]["verification_status"] == "verified"


def test_a_multi_label_subdomain_of_our_own_wildcard_still_needs_normal_verification(
    client, register_user, auth_header,
):
    owner = register_user(email="wc-owner2@example.com", username="wc_owner2")
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": "api.myshop.waf-it-kku.online"},
        headers=auth_header(owner["access_token"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["domain"]["verification_status"] == "pending"


@pytest.mark.parametrize("reserved", ["www.waf-it-kku.online", "main.waf-it-kku.online", "dash.waf-it-kku.online"])
def test_the_dashboards_own_reserved_subdomains_are_never_auto_verified(
    client, register_user, auth_header, reserved,
):
    owner = register_user(email=f"wc-{reserved.split('.')[0]}@example.com", username=f"wc_{reserved.split('.')[0]}")
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": reserved},
        headers=auth_header(owner["access_token"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["domain"]["verification_status"] == "pending"


def test_an_external_domain_is_never_auto_verified(client, register_user, auth_header):
    owner = register_user(email="wc-ext@example.com", username="wc_ext")
    origin_id = _create_origin(client, owner["access_token"], auth_header)

    resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": "shop.example.com"},
        headers=auth_header(owner["access_token"]),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["domain"]["verification_status"] == "pending"
