"""
Integration & Unit Test Suite for Milestone 2: WAF Rule Management with Deception Support.

Validates:
- Rule creation, retrieval, update, and deletion with actions: DECEIVE, BLOCK, CHALLENGE
- Backward compatibility: Legacy rules without action default to BLOCK and auto
- Schema validation: Invalid actions and templates rejected with HTTP 422
- ModSecurity .conf file syntax: status:418, status:401, status:403, and tag:'action:deceive'
- Special characters and escape safety preserved with action tags
- RBAC protection: Admin-only management, viewer read-only access
"""

import re
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from services.rule_manager import RuleManager, escape_secrule_string


# ==============================================================================
# Category A: CRUD Operations with Action (DECEIVE, BLOCK, CHALLENGE)
# ==============================================================================

def test_create_rule_deceive_action(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-01: Create rule with action='DECEIVE' and path_traversal template.
    Verifies HTTP 200 and conf file contains status:418, tag:'action:deceive', and template tag.
    """
    admin = register_user(email="admin-deceive1@example.com", username="admin_deceive1")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "100010",
            "variable": "REQUEST_URI",
            "operator": "@rx \\.\\./",
            "severity": "CRITICAL",
            "message": "Mitigate Path Traversal via Honeypot",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["rule_id"] == "100010"

    conf_file = tmp_path / "custom-100010.conf"
    assert conf_file.exists()
    content = conf_file.read_text(encoding="utf-8")
    assert "status:418" in content
    assert "tag:'action:deceive'" in content
    assert "tag:'template:path_traversal'" in content


def test_create_rule_sqli_deceive_action(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-02: Create rule with action='DECEIVE' and sql_injection template."""
    admin = register_user(email="admin-deceive2@example.com", username="admin_deceive2")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "100011",
            "variable": "ARGS",
            "operator": "@rx (?i)union\\s+select",
            "severity": "CRITICAL",
            "message": "Mitigate SQLi via Fake DB",
            "action": "DECEIVE",
            "deception_template": "sql_injection",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    content = (tmp_path / "custom-100011.conf").read_text(encoding="utf-8")
    assert "status:418" in content
    assert "tag:'action:deceive'" in content
    assert "tag:'template:sql_injection'" in content


def test_create_rule_explicit_block_action(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-03: Create rule with explicit action='BLOCK'.
    Verifies HTTP 200 and conf file contains status:403 without deception tags.
    """
    admin = register_user(email="admin-block@example.com", username="admin_block")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "100012",
            "variable": "REQUEST_HEADERS",
            "operator": "@contains badbot",
            "severity": "HIGH",
            "message": "Block Bad Bot Header",
            "action": "BLOCK",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    content = (tmp_path / "custom-100012.conf").read_text(encoding="utf-8")
    assert "status:403" in content
    assert "tag:'action:deceive'" not in content


def test_create_rule_challenge_action(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-04: Create rule with action='CHALLENGE'.
    Verifies HTTP 200 and conf file contains status:401 and tag:'action:challenge'.
    """
    admin = register_user(email="admin-challenge@example.com", username="admin_challenge")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "100013",
            "variable": "REQUEST_URI",
            "operator": "@contains /login",
            "severity": "MEDIUM",
            "message": "Challenge login endpoint",
            "action": "CHALLENGE",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    content = (tmp_path / "custom-100013.conf").read_text(encoding="utf-8")
    assert "status:401" in content
    assert "tag:'action:challenge'" in content


def test_get_rules_returns_action_and_template(client: TestClient, register_user, auth_header):
    """TC-CRUD-05: Calling GET /api/rules/ returns action and deception_template fields."""
    admin = register_user(email="admin-get@example.com", username="admin_get")
    headers = auth_header(admin["access_token"])

    # Create one DECEIVE and one CHALLENGE rule
    client.post(
        "/api/rules/",
        json={
            "id": "100014",
            "variable": "REQUEST_URI",
            "operator": "@rx /admin",
            "severity": "HIGH",
            "message": "Deceive admin probe",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        },
        headers=headers,
    )

    list_resp = client.get("/api/rules/", headers=headers)
    assert list_resp.status_code == 200
    rules = list_resp.json()["rules"]
    matching = [r for r in rules if r["id"] == "custom-100014"]
    assert len(matching) == 1
    assert matching[0]["action"] == "DECEIVE"
    assert matching[0]["deception_template"] == "path_traversal"


def test_update_rule_block_to_deceive(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-06: Update an existing BLOCK rule to DECEIVE.
    Verifies conf transitions from status:403 to status:418,tag:'action:deceive'.
    """
    admin = register_user(email="admin-update1@example.com", username="admin_update1")
    headers = auth_header(admin["access_token"])

    # 1. Create BLOCK rule
    client.post(
        "/api/rules/",
        json={
            "id": "100015",
            "variable": "ARGS",
            "operator": "@rx select",
            "severity": "CRITICAL",
            "message": "Block select",
            "action": "BLOCK",
        },
        headers=headers,
    )
    conf = (tmp_path / "custom-100015.conf").read_text(encoding="utf-8")
    assert "status:403" in conf

    # 2. Update to DECEIVE
    update_resp = client.put(
        "/api/rules/custom-100015",
        json={
            "variable": "ARGS",
            "operator": "@rx select",
            "severity": "CRITICAL",
            "message": "Deceive select probe",
            "action": "DECEIVE",
            "deception_template": "sqli",
        },
        headers=headers,
    )
    assert update_resp.status_code == 200, update_resp.text

    updated_conf = (tmp_path / "custom-100015.conf").read_text(encoding="utf-8")
    assert "status:418" in updated_conf
    assert "tag:'action:deceive'" in updated_conf
    assert "tag:'template:sqli'" in updated_conf


def test_update_rule_deceive_to_challenge(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-07: Update existing DECEIVE rule to CHALLENGE."""
    admin = register_user(email="admin-update2@example.com", username="admin_update2")
    headers = auth_header(admin["access_token"])

    client.post(
        "/api/rules/",
        json={
            "id": "100016",
            "variable": "REQUEST_URI",
            "operator": "@rx /test",
            "severity": "LOW",
            "message": "Deceive test",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        },
        headers=headers,
    )

    update_resp = client.put(
        "/api/rules/custom-100016",
        json={
            "variable": "REQUEST_URI",
            "operator": "@rx /test",
            "severity": "LOW",
            "message": "Challenge test",
            "action": "CHALLENGE",
        },
        headers=headers,
    )
    assert update_resp.status_code == 200

    updated_conf = (tmp_path / "custom-100016.conf").read_text(encoding="utf-8")
    assert "status:401" in updated_conf
    assert "tag:'action:challenge'" in updated_conf
    assert "status:418" not in updated_conf


def test_update_rule_challenge_to_block(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-08: Update existing CHALLENGE rule to BLOCK."""
    admin = register_user(email="admin-update3@example.com", username="admin_update3")
    headers = auth_header(admin["access_token"])

    client.post(
        "/api/rules/",
        json={
            "id": "100017",
            "variable": "REQUEST_URI",
            "operator": "@rx /api/v1",
            "severity": "MEDIUM",
            "message": "Challenge api",
            "action": "CHALLENGE",
        },
        headers=headers,
    )

    update_resp = client.put(
        "/api/rules/custom-100017",
        json={
            "variable": "REQUEST_URI",
            "operator": "@rx /api/v1",
            "severity": "MEDIUM",
            "message": "Block api",
            "action": "BLOCK",
        },
        headers=headers,
    )
    assert update_resp.status_code == 200

    updated_conf = (tmp_path / "custom-100017.conf").read_text(encoding="utf-8")
    assert "status:403" in updated_conf
    assert "tag:'action:challenge'" not in updated_conf


def test_delete_deception_rule(client: TestClient, register_user, auth_header, tmp_path):
    """TC-CRUD-09: Delete a rule created with DECEIVE action."""
    admin = register_user(email="admin-del@example.com", username="admin_del")
    headers = auth_header(admin["access_token"])

    client.post(
        "/api/rules/",
        json={
            "id": "100018",
            "variable": "REQUEST_URI",
            "operator": "@rx /delete-me",
            "severity": "LOW",
            "message": "Rule to delete",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        },
        headers=headers,
    )
    conf_file = tmp_path / "custom-100018.conf"
    assert conf_file.exists()

    del_resp = client.delete("/api/rules/custom-100018", headers=headers)
    assert del_resp.status_code == 200
    assert not conf_file.exists()

    list_resp = client.get("/api/rules/", headers=headers)
    assert all(r["id"] != "custom-100018" for r in list_resp.json()["rules"])


# ==============================================================================
# Category B: Backward Compatibility & Legacy Ingestion
# ==============================================================================

def test_legacy_conf_without_action_defaults_to_block(client: TestClient, register_user, auth_header, tmp_path):
    """TC-BC-01: Legacy .conf files without action tag default to BLOCK and auto."""
    admin = register_user(email="admin-legacy1@example.com", username="admin_legacy1")
    headers = auth_header(admin["access_token"])

    legacy_content = (
        '# Custom Rule 888001\n'
        'SecRule REQUEST_URI "@contains legacyprobe" \\\n'
        '"id:888001,phase:2,deny,status:403,severity:CRITICAL,log,msg:\'Legacy block rule\'"\n'
    )
    (tmp_path / "custom-888001.conf").write_text(legacy_content, encoding="utf-8")

    list_resp = client.get("/api/rules/", headers=headers)
    assert list_resp.status_code == 200
    rules = list_resp.json()["rules"]
    legacy_rule = next(r for r in rules if r["id"] == "custom-888001")
    assert legacy_rule["action"] == "BLOCK"
    assert legacy_rule["deception_template"] == "auto"
    assert legacy_rule["variable"] == "REQUEST_URI"
    assert legacy_rule["operator"] == "@contains legacyprobe"
    assert legacy_rule["severity"] == "CRITICAL"
    assert legacy_rule["message"] == "Legacy block rule"


def test_legacy_multiline_conf_parsing(client: TestClient, register_user, auth_header, tmp_path):
    """TC-BC-02: Legacy .conf file with multiline backslash continuations is parsed correctly."""
    admin = register_user(email="admin-legacy2@example.com", username="admin_legacy2")
    headers = auth_header(admin["access_token"])

    multiline_content = (
        '# Custom Rule 888002\n'
        'SecRule REQUEST_URI "@contains testattack" \\\n'
        '    "id:888002, \\\n'
        '    phase:1,\\\n'
        '    deny,\\\n'
        '    status:403,\\\n'
        '    severity:CRITICAL,\\\n'
        '    log,msg:\'Custom Rule: Block testattack keyword\'"\n'
    )
    (tmp_path / "custom-888002.conf").write_text(multiline_content, encoding="utf-8")

    list_resp = client.get("/api/rules/", headers=headers)
    assert list_resp.status_code == 200
    legacy_rule = next(r for r in list_resp.json()["rules"] if r["id"] == "custom-888002")
    assert legacy_rule["action"] == "BLOCK"
    assert legacy_rule["deception_template"] == "auto"
    assert legacy_rule["variable"] == "REQUEST_URI"
    assert legacy_rule["operator"] == "@contains testattack"
    assert legacy_rule["severity"] == "CRITICAL"
    assert legacy_rule["message"] == "Custom Rule: Block testattack keyword"


def test_create_rule_without_action_field_defaults_to_block(client: TestClient, register_user, auth_header, tmp_path):
    """TC-BC-03: Rule creation omitting action and deception_template defaults to BLOCK and auto."""
    admin = register_user(email="admin-legacy3@example.com", username="admin_legacy3")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "888003",
            "variable": "ARGS",
            "operator": "@rx (?i)legacy_omit",
            "severity": "HIGH",
            "message": "Omitted action rule",
        },
        headers=headers,
    )
    assert resp.status_code == 200

    content = (tmp_path / "custom-888003.conf").read_text(encoding="utf-8")
    assert "status:403" in content
    assert "tag:'action:deceive'" not in content

    list_resp = client.get("/api/rules/", headers=headers)
    rule = next(r for r in list_resp.json()["rules"] if r["id"] == "custom-888003")
    assert rule["action"] == "BLOCK"
    assert rule["deception_template"] == "auto"


def test_update_rule_without_action_field_defaults_to_block(client: TestClient, register_user, auth_header, tmp_path):
    """TC-BC-04: Rule update omitting action field defaults safely to BLOCK."""
    admin = register_user(email="admin-legacy4@example.com", username="admin_legacy4")
    headers = auth_header(admin["access_token"])

    client.post(
        "/api/rules/",
        json={
            "id": "888004",
            "variable": "ARGS",
            "operator": "@rx foo",
            "severity": "LOW",
            "message": "Init rule",
            "action": "DECEIVE",
        },
        headers=headers,
    )

    update_resp = client.put(
        "/api/rules/custom-888004",
        json={
            "variable": "ARGS",
            "operator": "@rx foo",
            "severity": "LOW",
            "message": "Updated without action",
        },
        headers=headers,
    )
    assert update_resp.status_code == 200

    list_resp = client.get("/api/rules/", headers=headers)
    rule = next(r for r in list_resp.json()["rules"] if r["id"] == "custom-888004")
    assert rule["action"] == "BLOCK"
    assert rule["deception_template"] == "auto"


def test_legacy_detection_gap_rule_without_status_defaults_to_block(client: TestClient, register_user, auth_header, tmp_path):
    """TC-BC-05: Rules lacking status code (e.g. pass,log detection rules) default to BLOCK."""
    admin = register_user(email="admin-legacy5@example.com", username="admin_legacy5")
    headers = auth_header(admin["access_token"])

    detection_rule_content = (
        'SecRule ARGS "@rx \'" \\\n'
        '"id:910000,phase:2,pass,log,severity:NOTICE,msg:\'DETECT-ONLY: single quote probe\'"\n'
    )
    (tmp_path / "custom-910000.conf").write_text(detection_rule_content, encoding="utf-8")

    list_resp = client.get("/api/rules/", headers=headers)
    assert list_resp.status_code == 200
    rule = next(r for r in list_resp.json()["rules"] if r["id"] == "custom-910000")
    assert rule["action"] == "BLOCK"
    assert rule["deception_template"] == "auto"


# ==============================================================================
# Category C: Schema Validation & Rejection (HTTP 422 / 400)
# ==============================================================================

@pytest.mark.parametrize("invalid_action", ["DROP", "PASS", "ALLOW", "LOG_ONLY", "INVALID"])
def test_create_rule_invalid_action_returns_422(client: TestClient, register_user, auth_header, invalid_action):
    """TC-VAL-01: Rejection of invalid action strings with HTTP 422."""
    admin = register_user(email="admin-val1@example.com", username="admin_val1")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "700001",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Invalid action rule",
            "action": invalid_action,
        },
        headers=headers,
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("non_string_action", [123, True, ["BLOCK"], {"action": "BLOCK"}])
def test_create_rule_non_string_action_returns_422(client: TestClient, register_user, auth_header, non_string_action):
    """TC-VAL-02: Non-string action values are rejected with HTTP 422."""
    admin = register_user(email="admin-val2@example.com", username="admin_val2")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "700002",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Non-string action rule",
            "action": non_string_action,
        },
        headers=headers,
    )
    assert resp.status_code == 422


def test_update_rule_invalid_action_returns_422(client: TestClient, register_user, auth_header):
    """TC-VAL-03: Updating an existing rule with an invalid action returns HTTP 422."""
    admin = register_user(email="admin-val3@example.com", username="admin_val3")
    headers = auth_header(admin["access_token"])

    resp = client.put(
        "/api/rules/custom-100001",
        json={
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Malformed update",
            "action": "MALICIOUS",
        },
        headers=headers,
    )
    assert resp.status_code == 422


def test_action_case_insensitive_normalization(client: TestClient, register_user, auth_header, tmp_path):
    """TC-VAL-04: Action strings are case-insensitive and normalized to uppercase."""
    admin = register_user(email="admin-val4@example.com", username="admin_val4")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "700004",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Lower deceive rule",
            "action": "deceive",
            "deception_template": "PATH_TRAVERSAL",
        },
        headers=headers,
    )
    assert resp.status_code == 200

    conf = (tmp_path / "custom-700004.conf").read_text(encoding="utf-8")
    assert "status:418" in conf
    assert "tag:'action:deceive'" in conf
    assert "tag:'template:path_traversal'" in conf

    list_resp = client.get("/api/rules/", headers=headers)
    rule = next(r for r in list_resp.json()["rules"] if r["id"] == "custom-700004")
    assert rule["action"] == "DECEIVE"
    assert rule["deception_template"] == "path_traversal"


def test_invalid_rule_id_returns_400_or_422(client: TestClient, register_user, auth_header):
    """TC-VAL-05: Non-numeric rule ID is rejected with HTTP 400."""
    admin = register_user(email="admin-val5@example.com", username="admin_val5")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "non-numeric-id",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Bad ID rule",
            "action": "DECEIVE",
        },
        headers=headers,
    )
    assert resp.status_code in (400, 422)


def test_create_rule_invalid_template_returns_422(client: TestClient, register_user, auth_header):
    """TC-VAL-06: Invalid deception template is rejected with HTTP 422."""
    admin = register_user(email="admin-val6@example.com", username="admin_val6")
    headers = auth_header(admin["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "700006",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Bad template rule",
            "action": "DECEIVE",
            "deception_template": "unsupported_template_xyz",
        },
        headers=headers,
    )
    assert resp.status_code == 422


# ==============================================================================
# Category D: Round-Trip Serialization & Config Syntax Verification
# ==============================================================================

def test_rule_manager_add_and_list_round_trip(tmp_path):
    """TC-RT-01: RuleManager add_rule and list_rules round-trip for DECEIVE, BLOCK, CHALLENGE."""
    rm = RuleManager()
    rm.rules_dir = str(tmp_path)
    rm.test_nginx = lambda: None
    rm.reload_nginx = lambda: None

    # Add DECEIVE rule
    rm.add_rule({
        "id": "600001",
        "variable": "REQUEST_URI",
        "operator": "@contains traversal",
        "severity": "CRITICAL",
        "message": "Path traversal honeypot",
        "action": "DECEIVE",
        "deception_template": "path_traversal",
    })

    # Add CHALLENGE rule
    rm.add_rule({
        "id": "600002",
        "variable": "REQUEST_HEADERS",
        "operator": "@contains bot",
        "severity": "MEDIUM",
        "message": "Challenge bot",
        "action": "CHALLENGE",
    })

    # Add BLOCK rule
    rm.add_rule({
        "id": "600003",
        "variable": "ARGS",
        "operator": "@rx sleep\\(\\d+\\)",
        "severity": "HIGH",
        "message": "Block blind SQLi",
        "action": "BLOCK",
    })

    rules = rm.list_rules()
    by_id = {r["id"]: r for r in rules}

    assert "custom-600001" in by_id
    r1 = by_id["custom-600001"]
    assert r1["action"] == "DECEIVE"
    assert r1["deception_template"] == "path_traversal"
    assert r1["variable"] == "REQUEST_URI"
    assert r1["operator"] == "@contains traversal"

    assert "custom-600002" in by_id
    r2 = by_id["custom-600002"]
    assert r2["action"] == "CHALLENGE"
    assert r2["deception_template"] == "auto"

    assert "custom-600003" in by_id
    r3 = by_id["custom-600003"]
    assert r3["action"] == "BLOCK"
    assert r3["deception_template"] == "auto"


def test_rule_manager_update_round_trip(tmp_path):
    """TC-RT-02: RuleManager update_rule correctly mutates configuration and list_rules parses it."""
    rm = RuleManager()
    rm.rules_dir = str(tmp_path)
    rm.test_nginx = lambda: None
    rm.reload_nginx = lambda: None

    rm.add_rule({
        "id": "600010",
        "variable": "REQUEST_URI",
        "operator": "@rx /admin",
        "severity": "HIGH",
        "message": "Initial block",
        "action": "BLOCK",
    })

    rm.update_rule("600010", {
        "variable": "REQUEST_URI",
        "operator": "@rx /admin",
        "severity": "CRITICAL",
        "message": "Switch to deception",
        "action": "DECEIVE",
        "deception_template": "path_traversal",
    })

    rules = rm.list_rules()
    r = next(r for r in rules if r["id"] == "custom-600010")
    assert r["action"] == "DECEIVE"
    assert r["deception_template"] == "path_traversal"
    assert r["severity"] == "CRITICAL"
    assert r["message"] == "Switch to deception"


def test_secrule_syntax_structure_for_deceive(tmp_path):
    """TC-RT-03: Verify written .conf text matches ModSecurity grammar."""
    rm = RuleManager()
    rm.rules_dir = str(tmp_path)
    rm.test_nginx = lambda: None
    rm.reload_nginx = lambda: None

    rm.add_rule({
        "id": "600020",
        "variable": "REQUEST_URI",
        "operator": "@rx (?i)/etc/passwd",
        "severity": "CRITICAL",
        "message": "Honeypot LFI",
        "action": "DECEIVE",
        "deception_template": "path_traversal",
    })

    conf_text = (tmp_path / "custom-600020.conf").read_text(encoding="utf-8")
    expected_line = (
        'SecRule REQUEST_URI "@rx (?i)/etc/passwd" \\\n'
        '"id:600020,phase:1,deny,status:418,tag:\'action:deceive\',tag:\'template:path_traversal\',severity:CRITICAL,log,msg:\'Honeypot LFI\'"\n'
    )
    assert expected_line in conf_text


def test_deceive_rule_with_special_characters_escaping(client: TestClient, register_user, auth_header, tmp_path):
    """TC-RT-04: Rule with action='DECEIVE' and attack payload strings with quotes and backslashes."""
    admin = register_user(email="admin-escape@example.com", username="admin_escape")
    headers = auth_header(admin["access_token"])

    attack_payload = "pwned\\' ctl:ruleRemoveById=900001"
    resp = client.post(
        "/api/rules/",
        json={
            "id": "600030",
            "variable": "ARGS",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": attack_payload,
            "action": "DECEIVE",
            "deception_template": "sqli",
        },
        headers=headers,
    )
    assert resp.status_code == 200

    conf_text = (tmp_path / "custom-600030.conf").read_text(encoding="utf-8")
    assert "status:418" in conf_text
    assert "tag:'action:deceive'" in conf_text

    # Verify msg field did not close early
    raw_msg_match = re.search(r"msg:'((?:[^'\\]|\\.)*)'", conf_text)
    assert raw_msg_match is not None
    decoded = re.sub(r"\\(.)", lambda m: m.group(1), raw_msg_match.group(1))
    assert decoded == attack_payload


# ==============================================================================
# Category F: Authorization & Role-Based Access Control (RBAC)
# ==============================================================================

def test_viewer_forbidden_from_creating_deceive_rule(client: TestClient, register_user, auth_header):
    """TC-RBAC-01: Viewer role is rejected with HTTP 403 when creating deception rule."""
    register_user(email="admin-rbac1@example.com", username="admin_rbac1")
    viewer = register_user(email="viewer-rbac1@example.com", username="viewer_rbac1", role="viewer")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.post(
        "/api/rules/",
        json={
            "id": "500001",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Viewer deception attempt",
            "action": "DECEIVE",
        },
        headers=viewer_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"


def test_viewer_forbidden_from_updating_rule_to_deceive(client: TestClient, register_user, auth_header):
    """TC-RBAC-02: Viewer role is rejected with HTTP 403 when updating rule to deception."""
    register_user(email="admin-rbac2@example.com", username="admin_rbac2")
    viewer = register_user(email="viewer-rbac2@example.com", username="viewer_rbac2", role="viewer")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.put(
        "/api/rules/custom-100001",
        json={
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Viewer update attempt",
            "action": "DECEIVE",
        },
        headers=viewer_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"


def test_viewer_forbidden_from_deleting_deceive_rule(client: TestClient, register_user, auth_header):
    """TC-RBAC-03: Viewer role is rejected with HTTP 403 when deleting rule."""
    register_user(email="admin-rbac3@example.com", username="admin_rbac3")
    viewer = register_user(email="viewer-rbac3@example.com", username="viewer_rbac3", role="viewer")
    viewer_headers = auth_header(viewer["access_token"])

    resp = client.delete("/api/rules/custom-100001", headers=viewer_headers)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"


def test_platform_viewer_forbidden_admin_can_view_deceive_rules(client: TestClient, register_user, auth_header):
    """TC-RBAC-04 (revised 2026-09-28, access-control audit): legacy global
    custom rules apply to every origin on the WAF with no per-origin
    ownership to filter by, so GET /api/rules/ was tightened to platform
    admin only -- a plain platform viewer used to see every dashboard-
    authored rule (including ones for origins they have no access to)."""
    admin = register_user(email="admin-rbac4@example.com", username="admin_rbac4")
    admin_headers = auth_header(admin["access_token"])

    client.post(
        "/api/rules/",
        json={
            "id": "500004",
            "variable": "REQUEST_URI",
            "operator": "@rx /probe",
            "severity": "LOW",
            "message": "Deception rule for viewer to see",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        },
        headers=admin_headers,
    )

    viewer = register_user(email="viewer-rbac4@example.com", username="viewer_rbac4", role="viewer")
    viewer_headers = auth_header(viewer["access_token"])

    assert client.get("/api/rules/", headers=viewer_headers).status_code == 403

    resp = client.get("/api/rules/", headers=admin_headers)
    assert resp.status_code == 200
    rules = resp.json()["rules"]
    deceive_rules = [r for r in rules if r.get("action") == "DECEIVE"]
    assert len(deceive_rules) >= 1
    assert any(r["id"] == "custom-500004" for r in deceive_rules)
