"""
Scenario: api/logs.py had zero test coverage despite being both a PII sink
(mask-preview/explain expose services/pii_masker.py directly to any
viewer-or-above user) and, historically, an injection sink (explain_log_by_id's
ClickHouse query was fixed to be parameterized as part of this project's H4
injection-cleanup round -- see the "ปิด injection 8 จุด" work). Two things this
file has no regression guard for yet:

1. Tenant isolation (_resolve_tenant_domains): a non-admin with zero origins,
   or one who names an origin/domain they do not own, must get an empty
   result -- never another tenant's logs, and never a ClickHouse query at
   all in the zero-origin case (matches the pattern already covered for
   analytics/copilot/ai_summary/cdn this session).
2. explain_log_by_id staying parameterized -- a regression back to string
   interpolation here would reopen exactly the injection class already fixed
   once (see services/clickhouse_service.py's escape_like_value docstring
   for the general version of this lesson).
"""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import origins as origins_module
from api import logs as logs_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(logs_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# --------------------------------------------------------- tenant isolation

def test_zero_origin_account_gets_empty_logs_and_never_queries_clickhouse(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(logs_module.ch, "connected", True)
    get_logs_spy = MagicMock()
    monkeypatch.setattr(logs_module.ch, "get_logs", get_logs_spy)

    register_user(email="logs-bootstrap@example.com", username="logs_bootstrap")
    viewer = register_user(email="logs-zero-origin@example.com", username="logs_zero_origin", role="viewer")
    headers = auth_header(viewer["access_token"])

    resp = client.get("/api/logs", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["logs"] == []
    assert body["total"] == 0
    assert get_logs_spy.call_count == 0, "a zero-origin account must never query ClickHouse at all"


def test_recent_logs_zero_origin_account_gets_empty_list(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(logs_module.ch, "connected", True)
    get_logs_spy = MagicMock()
    monkeypatch.setattr(logs_module.ch, "get_logs", get_logs_spy)

    register_user(email="logs-recent-bootstrap@example.com", username="logs_recent_bootstrap")
    viewer = register_user(email="logs-recent-zero@example.com", username="logs_recent_zero", role="viewer")

    resp = client.get("/api/logs/recent", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    assert resp.json() == {"logs": []}
    assert get_logs_spy.call_count == 0


def test_requesting_an_origin_you_do_not_own_returns_empty_not_another_tenants_logs(
    client: TestClient, register_user, auth_header, monkeypatch
):
    """A non-admin who owns domain A but asks for ?origin=domain-b.example
    (a domain they don't own) must get nothing back -- not domain B's real
    logs. This is the _resolve_tenant_domains __FORBIDDEN_TENANT_DOMAIN__
    path."""
    monkeypatch.setattr(logs_module.ch, "connected", True)
    get_logs_spy = MagicMock(return_value={"logs": [{"url": "/should-never-be-returned"}]})
    monkeypatch.setattr(logs_module.ch, "get_logs", get_logs_spy)

    register_user(email="logs-owner-bootstrap@example.com", username="logs_owner_bootstrap")
    owner = register_user(email="logs-owner@example.com", username="logs_owner", role="viewer")
    headers = auth_header(owner["access_token"])

    origin_resp = client.post(
        "/api/origins", json={"label": "MyLogsApp", "ip": "203.0.113.30", "port": 8080}, headers=headers,
    )
    assert origin_resp.status_code == 200
    origin_id = origin_resp.json()["id"]
    tenant_service_module.db.domains_table.put_item(Item={
        "id": "domain-logs-1", "origin_id": origin_id, "domain_name": "mylogsapp.example.com",
    })

    resp = client.get("/api/logs", params={"origin": "someone-elses-domain.example.com"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["logs"] == [], "must not leak another tenant's logs for a domain this user doesn't own"
    assert get_logs_spy.call_count == 0, "a forbidden-domain request must not reach ClickHouse at all"


def test_admin_can_view_all_logs_with_no_domain_filter(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(logs_module.ch, "connected", True)
    get_logs_spy = MagicMock(return_value={"logs": [], "total": 0, "page": 1, "limit": 20, "total_pages": 1})
    monkeypatch.setattr(logs_module.ch, "get_logs", get_logs_spy)

    admin = register_user(email="logs-admin@example.com", username="logs_admin")  # first user -> admin

    resp = client.get("/api/logs", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
    assert get_logs_spy.call_count == 1
    _, kwargs = get_logs_spy.call_args
    assert kwargs.get("domain_filter") is None, "admin with ALL scope must see every domain, not be filtered"


# -------------------------------------------------- explain_log_by_id injection guard

def test_explain_by_id_passes_log_id_as_a_bound_parameter_not_string_interpolation(
    client: TestClient, register_user, auth_header, monkeypatch
):
    """Regression guard for the injection class this project already fixed
    once (H4, ClickHouse LIKE-pattern + explain-by-id string interpolation).
    A malicious-looking log_id must reach ClickHouse only as a bound
    parameter value, never concatenated into the query text."""
    monkeypatch.setattr(logs_module.ch, "connected", True)
    fake_result = MagicMock()
    fake_result.result_rows = []
    query_spy = MagicMock(return_value=fake_result)
    monkeypatch.setattr(logs_module.ch, "client", MagicMock(query=query_spy))

    admin = register_user(email="logs-explain-admin@example.com", username="logs_explain_admin")
    malicious_id = "x' OR 1=1 --"

    resp = client.get(f"/api/logs/explain/{malicious_id}", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200

    assert query_spy.call_count == 1
    call_args, call_kwargs = query_spy.call_args
    query_text = call_args[0]
    assert malicious_id not in query_text, "the raw log_id must never be concatenated directly into the query string"
    assert call_kwargs.get("parameters", {}).get("log_id") == malicious_id, (
        "the log_id must be passed as a bound parameter so ClickHouse treats it as inert data"
    )


# ---------------------------------------------------------------- PII masking

def test_mask_preview_masks_pii_and_returns_zk_hash(client: TestClient, register_user, auth_header):
    admin = register_user(email="logs-mask-admin@example.com", username="logs_mask_admin")
    resp = client.post(
        "/api/logs/mask-preview",
        json={"text": "contact me at someone@example.com"},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "someone@example.com" not in body["masked_text"], "raw PII must not survive into the masked output"
    assert "EMAIL" in body["detected_pii_types"] or len(body["detected_pii_types"]) > 0
    assert body["zk_hash"], "a hash must be returned so the same input can be correlated without storing it raw"


def test_explain_masks_pii_in_the_sanitized_url(client: TestClient, register_user, auth_header, monkeypatch):
    monkeypatch.setattr(logs_module.ch, "connected", False)
    admin = register_user(email="logs-explain-pii-admin@example.com", username="logs_explain_pii_admin")

    resp = client.post(
        "/api/logs/explain",
        json={"url": "/profile?email=someone@example.com", "method": "GET"},
        headers=auth_header(admin["access_token"]),
    )
    assert resp.status_code == 200
    assert "someone@example.com" not in resp.json()["sanitized_url"]
