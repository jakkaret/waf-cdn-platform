"""
Scenario: SQLi - a quote in /api/ai/summarize-range's time bounds is
rejected, not executed.

Locks in the T6 fix: api/ai_summary.py's _parse_time_bound() only accepts
"%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", or "%Y-%m-%d" and raises
HTTPException(422) for anything else -- so a payload smuggled into start_time
or end_time is rejected by strptime before it can ever reach the
parameterised {start:DateTime}/{end:DateTime} ClickHouse queries below it.
Because the rejection happens in parsing, no query is ever built or run
against that value: "not executed" holds structurally, not just by luck.
"""
from fastapi.testclient import TestClient

from api import ai_summary as ai_summary_module

MALICIOUS_START = "2024-01-01 00:00:00' OR '1'='1"
MALICIOUS_END = "2024-01-02 00:00:00"


def test_quote_in_start_time_is_rejected_with_422(client: TestClient, register_user,
                                                    auth_header):
    user = register_user(email="analyst@example.com", username="analyst")

    resp = client.post(
        "/api/ai/summarize-range",
        json={"start_time": MALICIOUS_START, "end_time": MALICIOUS_END},
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 422
    assert "start_time" in resp.json()["detail"]


def test_quote_in_end_time_is_rejected_with_422(client: TestClient, register_user, auth_header):
    user = register_user(email="analyst2@example.com", username="analyst2")

    resp = client.post(
        "/api/ai/summarize-range",
        json={
            "start_time": "2024-01-01 00:00:00",
            "end_time": "2024-01-02 00:00:00'; DROP TABLE access_logs; --",
        },
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 422
    assert "end_time" in resp.json()["detail"]


def test_well_formed_time_range_is_accepted(client: TestClient, register_user, auth_header,
                                             monkeypatch):
    """Sanity check: the 422 above is about the malicious quote, not about the
    endpoint rejecting all input.

    gemini_service.generate_range_summary() is faked here because it is
    called unconditionally after the time range is parsed and would
    otherwise make a real network call to the Gemini API (forbidden by
    Ruling R3) -- irrelevant to what this test is checking.
    """

    async def _fake_summary(time_desc, stats):
        return "fake summary"

    monkeypatch.setattr(ai_summary_module.gemini_service, "generate_range_summary", _fake_summary)

    user = register_user(email="analyst3@example.com", username="analyst3")

    resp = client.post(
        "/api/ai/summarize-range",
        json={"start_time": "2024-01-01 00:00:00", "end_time": "2024-01-02 00:00:00"},
        headers=auth_header(user["access_token"]),
    )

    assert resp.status_code == 200
    assert resp.json()["success"] is True
