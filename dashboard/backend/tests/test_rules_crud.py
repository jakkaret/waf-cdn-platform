"""
Scenario: rules CRUD - create -> read -> delete a WAF rule.

This is the path T12's self-tuning will extend, so it needs to keep working
against the real services/rule_manager.py file-writing logic (not a shortcut
that never touches it). The docker-exec-backed nginx reload/test calls are
faked at their boundary (see tests/conftest.py); the rule file itself is
written for real, to a throwaway tmp_path directory.
"""
from fastapi.testclient import TestClient


def test_create_read_delete_rule(client: TestClient, register_user, auth_header):
    admin = register_user(email="rule-admin@example.com", username="rule_admin")
    headers = auth_header(admin["access_token"])

    create_resp = client.post(
        "/api/rules/",
        json={
            "id": "42017",
            "variable": "ARGS",
            "operator": "@rx (?i)union\\s+select",
            "severity": "CRITICAL",
            "message": "Blocked candidate SQLi rule",
        },
        headers=headers,
    )
    assert create_resp.status_code == 200, create_resp.text
    assert create_resp.json()["rule_id"] == "42017"

    list_resp = client.get("/api/rules/", headers=headers)
    assert list_resp.status_code == 200
    rules = list_resp.json()["rules"]
    matching = [r for r in rules if r["id"] == "custom-42017"]
    assert len(matching) == 1
    created_rule = matching[0]
    assert created_rule["variable"] == "ARGS"
    assert created_rule["severity"] == "CRITICAL"
    assert created_rule["message"] == "Blocked candidate SQLi rule"

    delete_resp = client.delete(f"/api/rules/{created_rule['id']}", headers=headers)
    assert delete_resp.status_code == 200

    final_list = client.get("/api/rules/", headers=headers).json()["rules"]
    assert all(r["id"] != "custom-42017" for r in final_list)


def test_delete_unknown_rule_returns_404(client: TestClient, register_user, auth_header):
    """Controller ruling R9: api/rules.py's delete_rule() used to raise
    HTTPException(404) from inside its own `try:` block, which its own
    `except Exception:` then re-caught and turned into a 500 (HTTPException
    subclasses Exception). Fixed by catching HTTPException before the
    generic Exception handler, matching update_rule's existing ordering
    three lines below it. This test was written, observed failing for that
    reason (500 instead of 404), removed per the original brief's
    constraint against changing api/ code, and restored here now that the
    fix is authorized and in place.
    """
    admin = register_user(email="rule-admin2@example.com", username="rule_admin2")
    resp = client.delete("/api/rules/custom-does-not-exist", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 404
