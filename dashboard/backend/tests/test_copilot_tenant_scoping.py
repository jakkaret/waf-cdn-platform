"""
Scenario: 2026-09-20 fix -- POST /api/copilot/chat's ClickHouse queries had
no tenant filter at all, so the AI Copilot chat answered every question with
system-wide telemetry, labelled in its own prompt as "the system under this
user's management". Confirmed live: a zero-origin account asking "which IPs
are attacking me" got back real attacker IPs, real attack payloads and real
timestamps belonging to other tenants.

Same two invariants as test_ai_summary_tenant_scoping.py, for the chat
endpoint: a non-admin account with zero registered origins never queries
ClickHouse at all, and an account that owns an origin gets a query scoped to
their own domain.

copilot_module isn't mounted in the shared conftest app (only
auth/origins/rules/ai_summary are) -- this file defines its own app/client
fixtures, same pattern as test_domains_router.py / test_ip_rules_router.py.
copilot_module calls Gemini directly via httpx.AsyncClient (not through a
gemini_service method like ai_summary.py does), so that's what's faked here
to avoid a real network call (Ruling R3) -- forced to fail, which exercises
the endpoint's own Fallback reply path, built from the same context_data
these tests are checking was scoped correctly.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import origins as origins_module
from api import copilot as copilot_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(copilot_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _failing_gemini_client():
    """Every candidate model call raises -- forces the endpoint straight to
    its own deterministic Fallback reply instead of a real network call."""
    client_cm = MagicMock()
    client_instance = MagicMock()
    client_instance.post = AsyncMock(side_effect=Exception("network calls are not allowed in tests"))
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=False)
    return client_cm


def test_zero_origin_account_never_queries_clickhouse(client: TestClient, register_user, auth_header, monkeypatch):
    monkeypatch.setattr(copilot_module.ch, "connected", True)
    query_spy = MagicMock(return_value=[])
    monkeypatch.setattr(copilot_module.ch, "query_stats", query_spy)

    register_user(email="cp-bootstrap@example.com", username="cp_bootstrap")
    viewer = register_user(email="cp-zero-origin@example.com", username="cp_zero_origin", role="viewer")

    with patch("api.copilot.httpx.AsyncClient", return_value=_failing_gemini_client()):
        resp = client.post(
            "/api/copilot/chat",
            json={"message": "มี IP ไหนพยายามโจมตีถี่ผิดปกติที่ควรบล็อกไหม?"},
            headers=auth_header(viewer["access_token"]),
        )

    assert resp.status_code == 200
    assert query_spy.call_count == 0, "a zero-origin account must never query ClickHouse at all"
    reply = resp.json()["reply"]
    # The Fallback reply is built straight from context_data -- for a
    # zero-scope account that must show zero blocks and no attacker IPs,
    # never data borrowed from other tenants.
    assert "0 ครั้ง" in reply
    assert "ไม่มี IP ผิดปกติในขณะนี้" in reply


def test_account_with_an_origin_gets_a_query_scoped_to_their_own_domain(
    client: TestClient, register_user, auth_header, monkeypatch
):
    monkeypatch.setattr(copilot_module.ch, "connected", True)
    query_spy = MagicMock(return_value=[])
    monkeypatch.setattr(copilot_module.ch, "query_stats", query_spy)

    # First registration in a fresh store becomes admin -- register a
    # throwaway one first so the real subject is a genuine non-admin owner.
    register_user(email="cp-owner-bootstrap@example.com", username="cp_owner_bootstrap")
    owner = register_user(email="cp-owner@example.com", username="cp_owner", role="viewer")
    headers = auth_header(owner["access_token"])

    origin_resp = client.post(
        "/api/origins", json={"label": "MyCopilotApp", "ip": "203.0.113.91", "port": 8081}, headers=headers,
    )
    assert origin_resp.status_code == 200
    origin_id = origin_resp.json()["id"]
    # Same reasoning as test_ai_summary_tenant_scoping.py: domains_module's
    # router isn't mounted here, write the domain directly into the shared
    # fake store get_user_origins_and_domains reads from.
    tenant_service_module.db.domains_table.put_item(Item={
        "id": "domain-copilot-1", "origin_id": origin_id, "domain_name": "mycopilotapp.example.com",
    })

    with patch("api.copilot.httpx.AsyncClient", return_value=_failing_gemini_client()):
        resp = client.post(
            "/api/copilot/chat",
            json={"message": "สรุปภาพรวมทราฟฟิกวันนี้"},
            headers=headers,
        )

    assert resp.status_code == 200
    assert query_spy.call_count > 0, "an account with a real origin should still query ClickHouse"
    for call in query_spy.call_args_list:
        query_text = call.args[0] if call.args else call.kwargs.get("query", "")
        assert "mycopilotapp" in query_text.lower() or "203.0.113.91" in query_text, (
            f"query was not scoped to the owner's domain/ip: {query_text}"
        )
