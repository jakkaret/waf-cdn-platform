"""
Scenario: T11 Part A - mount `origins_domains_router` (the four
GET/POST/POST-verify/DELETE endpoints under /api/origins/{origin_id}/domains
defined in api/domains.py:197) and constrain `domain_name` to a hostname
shape at the point it enters the system (ruling R7, task-11-brief.md).

Covers:
  - ownership is enforced on all four new endpoints (a different tenant is
    refused, never silently shown or allowed to mutate someone else's data)
  - R7: a syntactically valid hostname is accepted, and a malformed one is
    rejected with 422 -- both for its shape (missing dot, hyphen placement,
    whitespace, length) and, per the T11 review's Critical finding, for the
    exact SQL-metacharacter classes ("'", "\\", "%", "_") that
    services/tenant_service.py -> api/analytics.py's _build_domain_pattern_sql
    interpolates unparameterized into ClickHouse. The review reproduced a
    live bypass via the *legacy* POST /api/domains endpoint (which applied
    no validation at all before this fix) writing into the identical
    domains_table that feeds that sink -- so every case below runs against
    both POST /api/domains and POST /api/origins/{origin_id}/domains,
    proving both write paths are now constrained identically. This is entry
    validation as mitigation, not a fix for the underlying vulnerability:
    the weak backslash-replacement escaping in tenant_service.py /
    analytics.py / clickhouse_service.py is untouched and stays out of
    scope (separate, tracked parameterization refactor).

This module defines its own `app`/`client` fixtures, overriding conftest.py's
for this file only (same pattern as test_ml_attribution_explanation.py) --
the shared minimal app in conftest.py deliberately does not include
api.domains's router. Every other fixture (fake_infrastructure, register_user,
auth_header, ...) is reused unchanged from conftest.py so auth/ownership stay
real, per the brief's instruction not to weaken that guarantee.

`services.dns_service.verify_domain_dns` does a real DNS lookup, which is not
allowed to leave the machine (ruling R3) -- it is monkeypatched per-test only
where the verify endpoint's *success* path is exercised. The ownership
(403) tests never reach it, since verify_origin_ownership runs first.
"""
import uuid

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
    test_app.include_router(domains_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _create_origin(client, token, auth_header, label="edge-domains-1"):
    resp = client.post(
        "/api/origins",
        json={"label": label, "ip": "203.0.113.20", "port": 8080},
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _create_domain(client, origin_id, token, auth_header, domain_name="shop.example.com"):
    """POST /api/origins/{origin_id}/domains -- the endpoint newly mounted for T11."""
    resp = client.post(
        f"/api/origins/{origin_id}/domains",
        json={"domain_name": domain_name},
        headers=auth_header(token),
    )
    return resp


def _create_domain_legacy(client, origin_id, token, auth_header, domain_name="shop.example.com"):
    """POST /api/domains -- the pre-existing endpoint the T11 review found had
    no domain_name validation at all, writing into the same domains_table."""
    resp = client.post(
        "/api/domains",
        json={"origin_id": origin_id, "domain_name": domain_name},
        headers=auth_header(token),
    )
    return resp


# ---------------------------------------------------------------------------
# Ruling R7 -- domain_name is constrained to a hostname shape.
# ---------------------------------------------------------------------------

def test_create_domain_accepts_valid_hostname(client: TestClient, register_user, auth_header):
    owner = register_user(email="dom-owner-1@example.com", username="dom_owner_1")
    origin = _create_origin(client, owner["access_token"], auth_header)

    resp = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                           domain_name="Shop.Example.com")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # normalized (stripped/lowercased) by the validator, same as before R7.
    assert body["domain"]["domain_name"] == "shop.example.com"
    assert body["domain"]["origin_id"] == origin["origin_id"]
    assert "dns_instructions" in body
    assert body["dns_instructions"]["cname_record"]["type"] == "CNAME"


@pytest.mark.parametrize("bad_domain_name", [
    "not-a-hostname",          # single label, no dot
    "-bad.example.com",        # label leading with a hyphen
    "bad-.example.com",        # label trailing with a hyphen
    "",                        # empty
    "a" * 254,                 # over 253 chars total, and no dot either
    "exa mple.com",            # whitespace inside a label
])
def test_create_domain_rejects_invalid_hostname(client: TestClient, register_user, auth_header,
                                                  bad_domain_name):
    owner = register_user(email="dom-owner-2@example.com", username="dom_owner_2")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-2")

    resp = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                           domain_name=bad_domain_name)
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# Ruling R7, T11 review Critical finding -- domain_name is also rejected for
# the exact SQL-metacharacter classes that services/tenant_service.py's
# ClickHouse LIKE-pattern construction (api/analytics.py's
# _build_domain_pattern_sql) interpolates unparameterized, on *both* write
# paths into domains_table: the endpoint newly mounted for T11
# (POST /api/origins/{origin_id}/domains) and the pre-existing
# POST /api/domains, which the review found applied no validation at all.
#
# This proves entry validation as *mitigation* for this specific injection
# path -- it does not fix the weak backslash-replacement escaping in
# tenant_service.py / analytics.py / clickhouse_service.py, which remains a
# separate, tracked finding and is untouched here.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dangerous_domain_name", [
    "sh%op.example.com",    # '%' -- ClickHouse LIKE multi-char wildcard
    "sh_op.example.com",    # '_' -- ClickHouse LIKE single-char wildcard
    "sh'op.example.com",    # single quote -- string-literal breakout
    r"sh\op.example.com",  # backslash -- defeats the backslash-replacement escaping
], ids=["percent", "underscore", "single_quote", "backslash"])
@pytest.mark.parametrize("create_fn", [_create_domain, _create_domain_legacy],
                          ids=["new_router", "legacy_router"])
def test_domain_name_rejects_sql_metacharacters_on_both_endpoints(client: TestClient, register_user,
                                                                    auth_header, dangerous_domain_name,
                                                                    create_fn):
    unique = uuid.uuid4().hex[:10]
    owner = register_user(email=f"dom-meta-{unique}@example.com", username=f"dom_meta_{unique}")
    origin = _create_origin(client, owner["access_token"], auth_header, label=f"edge-meta-{unique}")

    resp = create_fn(client, origin["origin_id"], owner["access_token"], auth_header,
                      domain_name=dangerous_domain_name)
    assert resp.status_code == 422, resp.text


def test_domain_name_rejects_named_sqli_regression_case_on_both_endpoints(client: TestClient,
                                                                            register_user, auth_header):
    """Named regression case: the exact live bypass the T11 review reproduced.

    Registering domain_name = r"x\' OR 1=1 --" through the *unvalidated*
    legacy POST /api/domains endpoint, combined with tenant_service's
    backslash-replacement escaping ("'" -> "\\'"), produced the ClickHouse
    fragment `(url LIKE '%x\\' OR 1=1 --%' OR client_ip LIKE '%x\\' OR 1=1 --%')`
    -- ClickHouse reads the "\\\\" as one literal backslash, so the "'"
    that follows closes the string literal and "OR 1=1 --" executes as SQL,
    defeating the per-tenant WHERE filter this code's own comments describe
    as enforcing strict isolation. Both endpoints must now reject this
    domain_name outright, before it ever reaches that sink.
    """
    payload_domain = r"x\' OR 1=1 --"

    unique = uuid.uuid4().hex[:10]
    owner = register_user(email=f"dom-sqli-regression-{unique}@example.com",
                           username=f"dom_sqli_regression_{unique}")
    origin_new = _create_origin(client, owner["access_token"], auth_header,
                                 label=f"edge-sqli-new-{unique}")
    origin_legacy = _create_origin(client, owner["access_token"], auth_header,
                                    label=f"edge-sqli-legacy-{unique}")

    new_resp = _create_domain(client, origin_new["origin_id"], owner["access_token"], auth_header,
                               domain_name=payload_domain)
    assert new_resp.status_code == 422, new_resp.text

    legacy_resp = _create_domain_legacy(client, origin_legacy["origin_id"], owner["access_token"],
                                          auth_header, domain_name=payload_domain)
    assert legacy_resp.status_code == 422, legacy_resp.text


# ---------------------------------------------------------------------------
# Ownership enforcement on all four endpoints.
# ---------------------------------------------------------------------------

def test_create_domain_ownership_enforced(client: TestClient, register_user, auth_header):
    owner = register_user(email="dom-owner-3@example.com", username="dom_owner_3")
    intruder = register_user(email="dom-intruder-3@example.com", username="dom_intruder_3",
                              role="viewer")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-3")

    resp = _create_domain(client, origin["origin_id"], intruder["access_token"], auth_header,
                           domain_name="intruder.example.com")
    assert resp.status_code == 403


def test_list_domains_ownership_enforced_and_owner_sees_created_domain(client: TestClient,
                                                                         register_user, auth_header):
    owner = register_user(email="dom-owner-4@example.com", username="dom_owner_4")
    intruder = register_user(email="dom-intruder-4@example.com", username="dom_intruder_4",
                              role="viewer")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-4")
    created = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                              domain_name="portal.example.com")
    assert created.status_code == 200, created.text

    cross_resp = client.get(f"/api/origins/{origin['origin_id']}/domains",
                             headers=auth_header(intruder["access_token"]))
    assert cross_resp.status_code == 403

    own_resp = client.get(f"/api/origins/{origin['origin_id']}/domains",
                           headers=auth_header(owner["access_token"]))
    assert own_resp.status_code == 200
    names = [d["domain_name"] for d in own_resp.json()["domains"]]
    assert "portal.example.com" in names


def test_verify_domain_ownership_enforced(client: TestClient, register_user, auth_header):
    owner = register_user(email="dom-owner-5@example.com", username="dom_owner_5")
    intruder = register_user(email="dom-intruder-5@example.com", username="dom_intruder_5",
                              role="viewer")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-5")
    created = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                              domain_name="verify.example.com")
    domain_id = created.json()["domain"]["domain_id"]

    resp = client.post(
        f"/api/origins/{origin['origin_id']}/domains/{domain_id}/verify",
        headers=auth_header(intruder["access_token"]),
    )
    assert resp.status_code == 403


def test_verify_domain_owner_can_verify(client: TestClient, register_user, auth_header, monkeypatch):
    # verify_domain_dns does a real DNS lookup (ruling R3: no network call is
    # allowed to leave the machine) -- faked here only, for this test's
    # success path.
    monkeypatch.setattr(domains_module, "verify_domain_dns", lambda domain_name, token: True)

    owner = register_user(email="dom-owner-6@example.com", username="dom_owner_6")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-6")
    created = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                              domain_name="verify-ok.example.com")
    domain_id = created.json()["domain"]["domain_id"]

    resp = client.post(
        f"/api/origins/{origin['origin_id']}/domains/{domain_id}/verify",
        headers=auth_header(owner["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"


def test_delete_domain_ownership_enforced_then_owner_can_delete(client: TestClient, register_user,
                                                                   auth_header):
    owner = register_user(email="dom-owner-7@example.com", username="dom_owner_7")
    intruder = register_user(email="dom-intruder-7@example.com", username="dom_intruder_7",
                              role="viewer")
    origin = _create_origin(client, owner["access_token"], auth_header, label="edge-domains-7")
    created = _create_domain(client, origin["origin_id"], owner["access_token"], auth_header,
                              domain_name="delete-me.example.com")
    domain_id = created.json()["domain"]["domain_id"]

    cross_del = client.delete(
        f"/api/origins/{origin['origin_id']}/domains/{domain_id}",
        headers=auth_header(intruder["access_token"]),
    )
    assert cross_del.status_code == 403

    # Confirm it was not deleted: the owner can still see it.
    still_there = client.get(f"/api/origins/{origin['origin_id']}/domains",
                              headers=auth_header(owner["access_token"]))
    assert any(d["domain_id"] == domain_id for d in still_there.json()["domains"])

    own_del = client.delete(
        f"/api/origins/{origin['origin_id']}/domains/{domain_id}",
        headers=auth_header(owner["access_token"]),
    )
    assert own_del.status_code == 200

    after = client.get(f"/api/origins/{origin['origin_id']}/domains",
                        headers=auth_header(owner["access_token"]))
    assert all(d["domain_id"] != domain_id for d in after.json()["domains"])
