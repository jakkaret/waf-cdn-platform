"""
Scenario: 2026-09-20 fix -- POST /api/ai/summarize-range's ClickHouse queries
had no tenant filter at all (only a time range), so the "AI Summary" button
shown on nearly every page summarized every tenant's traffic, not the
calling account's own. Confirmed live: a zero-origin account got back real
attacker IPs and attack payloads belonging to other tenants.

Covers the two invariants the fix establishes:
  - a non-admin account with zero registered origins never queries
    ClickHouse at all (the strongest possible guarantee: no query, no way to
    leak anything) and gets an honest "no data yet" summary instead of
    Gemini improvising over global stats,
  - an account that does own an origin gets a query that's actually scoped
    to their own domain, not the whole access_logs table.

gemini_service.generate_range_summary() is faked throughout (same reasoning
as test_ai_summary_sqli.py's own fake): it would otherwise make a real
network call to the Gemini API, forbidden by Ruling R3 and irrelevant to
what these tests check.
"""
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from api import ai_summary as ai_summary_module


def _fake_generate_summary(monkeypatch, capture: dict):
    async def _fake(time_desc, stats):
        capture["stats"] = stats
        return "fake summary"
    monkeypatch.setattr(ai_summary_module.gemini_service, "generate_range_summary", _fake)


def test_zero_origin_account_never_queries_clickhouse_and_gets_an_honest_reply(
    client: TestClient, register_user, auth_header, monkeypatch
):
    captured = {}
    _fake_generate_summary(monkeypatch, captured)

    # Force ch.connected = True so the *absence* of any query call is a real
    # signal (not just "ClickHouse happened to be unreachable in this test").
    monkeypatch.setattr(ai_summary_module.ch, "connected", True)
    query_spy = MagicMock()
    monkeypatch.setattr(ai_summary_module.ch, "client", MagicMock(query=query_spy))

    # First registered user in a fresh fake store becomes admin (conftest's
    # own bootstrap rule) -- register a throwaway admin first so this one is
    # a genuine zero-scope viewer.
    register_user(email="ai-bootstrap@example.com", username="ai_bootstrap")
    viewer = register_user(email="ai-zero-origin@example.com", username="ai_zero_origin", role="viewer")

    resp = client.post(
        "/api/ai/summarize-range",
        json={"start_time": "2024-01-01 00:00:00", "end_time": "2024-01-02 00:00:00"},
        headers=auth_header(viewer["access_token"]),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert query_spy.call_count == 0, "a zero-origin account must never query ClickHouse at all"
    assert body["stats"]["total_requests"] == 0
    assert body["stats"]["top_attacker_ips"] == []
    assert "ยังไม่มี Origin Server" in body["ai_executive_summary"]
    assert "stats" not in captured, "generate_range_summary must not even be called for a zero-scope account"


def test_account_with_an_origin_gets_a_query_scoped_to_their_own_domain(
    client: TestClient, register_user, auth_header, monkeypatch
):
    captured = {}
    _fake_generate_summary(monkeypatch, captured)

    monkeypatch.setattr(ai_summary_module.ch, "connected", True)
    query_spy = MagicMock()
    result = MagicMock()
    result.result_rows = []
    query_spy.return_value = result
    monkeypatch.setattr(ai_summary_module.ch, "client", MagicMock(query=query_spy))

    # First registration in a fresh store always becomes admin (conftest's
    # bootstrap rule) -- register a throwaway one first so ai_owner is a
    # genuine non-admin whose scope is actually exercised, not the
    # is_admin=True "sees everything" branch.
    register_user(email="ai-owner-bootstrap@example.com", username="ai_owner_bootstrap")
    owner = register_user(email="ai-owner@example.com", username="ai_owner", role="viewer")
    headers = auth_header(owner["access_token"])
    origin_resp = client.post(
        "/api/origins", json={"label": "MyApp", "ip": "203.0.113.90", "port": 8080}, headers=headers,
    )
    assert origin_resp.status_code == 200
    origin_id = origin_resp.json()["id"]
    # domains_module's router isn't mounted in the shared test app (only
    # auth/origins/rules/ai_summary are, per conftest.py) -- write the domain
    # record directly into the same fake store ai_summary_module.db shares
    # with everything else, same as reading it back via
    # get_user_origins_and_domains's own db.domains_table.scan() would see.
    ai_summary_module.db.domains_table.put_item(Item={
        "id": "domain-1", "origin_id": origin_id, "domain_name": "myapp.example.com",
    })

    resp = client.post(
        "/api/ai/summarize-range",
        json={"start_time": "2024-01-01 00:00:00", "end_time": "2024-01-02 00:00:00"},
        headers=headers,
    )

    assert resp.status_code == 200
    assert query_spy.call_count > 0, "an account with a real origin should still query ClickHouse"
    # Every call's query string must carry a real scoping clause, not "WHERE
    # timestamp ... " alone -- i.e. it must mention this account's own domain
    # keyword rather than reading the whole table.
    for call in query_spy.call_args_list:
        query_text = call.args[0] if call.args else call.kwargs.get("query", "")
        assert "myapp" in query_text.lower() or "203.0.113.90" in query_text, (
            f"query was not scoped to the owner's domain/ip: {query_text}"
        )
