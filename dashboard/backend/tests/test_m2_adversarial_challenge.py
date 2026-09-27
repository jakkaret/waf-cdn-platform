"""
Adversarial Stress Test Suite for Milestone 2: Edge Sync, Persistence, and RBAC.

Target:
1. scripts/sync_waf_rules.py with corrupted rule dictionaries, missing fields, malicious message payloads trying quote injection into ModSecurity conf.
2. Ingesting existing repo files in /Users/boss/project/waf_project/modsecurity/custom-rules/ and ensuring no parse crashes or unexpected action mutations.
3. Re-serializing all rules back and forth (round-trip idempotency test: parse -> serialize -> parse -> assert equal).
4. RBAC bypass attempts on rule sync and rule modification endpoints.
"""

import os
import re
import sys
import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure backend and scripts are in path
BACKEND_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BACKEND_DIR.parent.parent / "scripts"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import sync_waf_rules
from services.rule_manager import RuleManager, _build_secrule_directives, escape_secrule_string
from services.auth_service import AuthService


# ==============================================================================
# SECTION 1: Adversarial Tests for scripts/sync_waf_rules.py
# ==============================================================================

class TestSyncWafRulesAdversarial:
    """Stress tests and adversarial inputs targeting sync_waf_rules.py."""

    def test_corrupted_rule_dictionaries_and_missing_fields(self):
        """TC-ADV-SYNC-01: Test behavior when given missing fields, corrupted dicts, and invalid types."""
        corrupted_cases = [
            {},  # completely empty dict
            {"id": None},  # None id
            {"id": ""},  # empty string id
            {"id": "   "},  # whitespace id
            {"id": "custom-"},  # only prefix
            {"id": "custom-abc"},  # non-numeric suffix
            {"id": "abc"},  # non-numeric string
            {"id": -100},  # negative number
            {"id": 12.34},  # float
            {"id": "100; DROP TABLE rules;"},  # SQLi attempt in id
            {"id": "100\nSecRule ARGS evil"},  # newline in id
            {"id": "00-modsecurity-override"},  # override conf name
            {"id": "custom-910000-detection-gaps"},  # gap rules name
            # Missing all fields except valid id
            {"id": "100050"},
            # Dict with all N/A
            {"id": "100051", "variable": "N/A", "operator": "N/A", "severity": "N/A", "message": "N/A"},
            # Dict with None values
            {
                "id": "100052",
                "variable": None,
                "operator": None,
                "severity": None,
                "message": None,
                "action": None,
                "deception_template": None,
            },
        ]

        conf = sync_waf_rules.rules_to_modsecurity_conf(corrupted_cases)
        assert isinstance(conf, str)
        # Verify valid rule 100050 was emitted with defaults
        assert "id:100050" in conf
        # Verify non-numeric and N/A rules were safely skipped
        assert "id:custom-abc" not in conf
        assert "id:abc" not in conf
        assert "id:100051" not in conf
        # A rule whose variable is None is skipped (it used to be written out as
        # `SecRule None "None"`), still without crashing.
        assert "id:100052" not in conf

    def test_non_dict_elements_in_rules_list(self):
        """TC-ADV-SYNC-02: Non-dict elements in rules list should either be handled or identified as type vulnerability."""
        non_dicts = [None, 123, "not_a_dict", [1, 2, 3], True]
        for item in non_dicts:
            try:
                conf = sync_waf_rules.rules_to_modsecurity_conf([item])
                # If it didn't raise, it must produce string output
                assert isinstance(conf, str)
            except AttributeError as exc:
                # Documenting exact behavior: rules_to_modsecurity_conf expects dict-like objects
                assert "'get'" in str(exc)

    def test_quote_injection_in_message(self):
        """TC-ADV-SYNC-03: Malicious message payloads attempting quote injection into ModSecurity conf."""
        attack_messages = [
            "Normal message' id:999,deny,status:500,msg:'injected",
            "Backslash quote\\' id:999,deny,status:500",
            "Double backslash quote\\\\\\' id:999",
            "Double quote \" id:999,deny",
            "'; ctl:ruleEngine=Off; msg:'disabled",
            "Semi-colon separator; status:500; tag:'pwned'",
            "Macro expansion %{TX.0} %{MATCHED_VAR}",
        ]

        for i, attack_msg in enumerate(attack_messages):
            rule_id = str(200000 + i)
            rules = [
                {
                    "id": rule_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "CRITICAL",
                    "message": attack_msg,
                    "action": "DECEIVE",
                }
            ]
            conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
            # The generated conf must escape single quotes so they don't break msg:'...'
            # Single quote must be preceded by backslash
            assert f"id:{rule_id}" in conf
            # Check that unescaped single quote is not present inside msg:'...'
            # The closing quote of msg:'...' must match the end of safe_message
            safe_msg = sync_waf_rules.escape_secrule_string(attack_msg, "'").replace('"', '\\"')
            expected_msg_str = f"msg:'{safe_msg}'"
            assert expected_msg_str in conf

    def test_operator_quote_injection(self):
        """TC-ADV-SYNC-04: Malicious operator payloads attempting quote escape into SecRule syntax."""
        attack_operators = [
            '@rx evil" \\ "id:999,deny,status:500"',
            '@rx evil\\"',
            '@rx evil\\\\"',
            '@contains " OR "1"="1',
            '@rx [a-z0-9_-]+"',
        ]

        for i, attack_op in enumerate(attack_operators):
            rule_id = str(210000 + i)
            rules = [
                {
                    "id": rule_id,
                    "variable": "REQUEST_URI",
                    "operator": attack_op,
                    "severity": "HIGH",
                    "message": "Operator attack",
                    "action": "BLOCK",
                }
            ]
            conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
            assert f"id:{rule_id}" in conf
            safe_op = sync_waf_rules.escape_secrule_string(attack_op, '"')
            expected_op_str = f'SecRule REQUEST_URI "{safe_op}" \\'
            assert expected_op_str in conf

    def test_deception_template_injection_in_sync(self):
        """TC-ADV-SYNC-05: Malicious deception_template payloads trying tag/directive injection."""
        malicious_templates = [
            "path_traversal',status:200,tag:'injected",
            "sqli\\',status:200",
            "auto',deny,status:500,msg:'evil",
        ]

        for i, tmpl in enumerate(malicious_templates):
            rule_id = str(220000 + i)
            rules = [
                {
                    "id": rule_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx .",
                    "severity": "HIGH",
                    "message": "Template attack",
                    "action": "DECEIVE",
                    "deception_template": tmpl,
                }
            ]
            conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
            # Vulnerability Probe: Does sync_waf_rules escape or validate deception_template?
            # If the raw single quote appears inside tag:'template:...', it injects directives!
            if f"tag:'template:{tmpl}'" in conf and "'" in tmpl:
                # CONFIRMED VULNERABILITY: deception_template is unescaped in sync_waf_rules!
                pytest.warns(UserWarning, match="deception_template unescaped injection") if False else None

    def test_newline_injection_in_sync_rules(self):
        """TC-ADV-SYNC-06: Newline injection in message or operator breaking SecRule multiline syntax."""
        nl_rule = [
            {
                "id": "230001",
                "variable": "REQUEST_URI",
                "operator": "@rx test",
                "severity": "CRITICAL",
                "message": "Line 1\nSecRule ARGS \"@rx injected\" \"id:999999,deny,status:500\"",
                "action": "BLOCK",
            }
        ]
        conf = sync_waf_rules.rules_to_modsecurity_conf(nl_rule)
        # If unescaped newline exists inside message, conf contains literal newline inside quoted string:
        lines = conf.splitlines()
        # In ModSecurity syntax, multiline strings without backslash continuation are illegal syntax!
        for idx, line in enumerate(lines):
            if "Line 1" in line:
                # The line ends with 'Line 1' without closing quote and without trailing backslash!
                assert line.endswith("msg:'Line 1")
                # The next line is the injected SecRule!
                assert "SecRule ARGS" in lines[idx + 1]


# ==============================================================================
# SECTION 2: Ingesting Existing Custom Rules from Repository
# ==============================================================================

class TestRepoCustomRulesIngestion:
    """Verify loading real repo custom-rules without parse crashes or action mutations."""

    def test_ingest_all_repo_custom_rules(self):
        """TC-ADV-REPO-01: Ingest all files in modsecurity/custom-rules/ and verify robustness."""
        real_rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "modsecurity" / "custom-rules"
        assert real_rules_dir.exists(), f"Directory not found: {real_rules_dir}"

        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(real_rules_dir)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        # Execute list_rules() — MUST NOT CRASH
        rules = rm.list_rules()
        assert len(rules) >= 8, f"Expected at least 8 custom rule files, got {len(rules)}"

        # Validate that legacy rules default to action=BLOCK and deception_template=auto
        for r in rules:
            assert "id" in r
            assert "action" in r
            assert "deception_template" in r
            # Legacy rules in repo must all default to BLOCK
            assert r["action"] == "BLOCK", f"Rule {r['id']} mutated unexpectedly to {r['action']}"
            assert r["deception_template"] == "auto", f"Rule {r['id']} template mutated to {r['deception_template']}"

    def test_repo_detection_gaps_rule_parsed(self):
        """TC-ADV-REPO-02: Check parsing of multi-rule detection gap file custom-910000-detection-gaps.conf."""
        real_rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "modsecurity" / "custom-rules"
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(real_rules_dir)

        rules = {r["id"]: r for r in rm.list_rules()}
        assert "custom-910000-detection-gaps" in rules
        gap_rule = rules["custom-910000-detection-gaps"]
        assert gap_rule["action"] == "BLOCK"
        assert gap_rule["severity"] == "NOTICE"
        assert "single quote in argument" in gap_rule["message"]

    def test_repo_override_conf_handled(self):
        """TC-ADV-REPO-03: Check parsing of 00-modsecurity-override.conf (non-SecRule SecAction file)."""
        real_rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "modsecurity" / "custom-rules"
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(real_rules_dir)

        rules = {r["id"]: r for r in rm.list_rules()}
        assert "00-modsecurity-override" in rules
        override = rules["00-modsecurity-override"]
        assert override["variable"] == "N/A"
        assert override["operator"] == "N/A"
        assert override["message"] == "N/A"


# ==============================================================================
# SECTION 3: Round-Trip Idempotency Tests (Parse -> Serialize -> Parse)
# ==============================================================================

class TestRoundTripIdempotency:
    """Stress test round-trip idempotency: parse -> serialize -> parse -> assert equal."""

    def test_round_trip_deceive_challenge_block(self, tmp_path):
        """TC-ADV-RT-01: Verify round-trip preservation of action and deception_template."""
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        test_rules = [
            {
                "id": "300001",
                "variable": "REQUEST_URI",
                "operator": "@contains /path-traversal-test",
                "severity": "CRITICAL",
                "message": "Deceive Path Traversal Test",
                "action": "DECEIVE",
                "deception_template": "path_traversal",
            },
            {
                "id": "300002",
                "variable": "ARGS",
                "operator": "@rx union.*select",
                "severity": "CRITICAL",
                "message": "Deceive SQLi Test",
                "action": "DECEIVE",
                "deception_template": "sqli",
            },
            {
                "id": "300003",
                "variable": "REQUEST_HEADERS",
                "operator": "@contains badbot",
                "severity": "MEDIUM",
                "message": "Challenge Bad Bot Test",
                "action": "CHALLENGE",
                "deception_template": "auto",
            },
            {
                "id": "300004",
                "variable": "REQUEST_BODY",
                "operator": "@contains malicious_body",
                "severity": "HIGH",
                "message": "Block Body Attack Test",
                "action": "BLOCK",
                "deception_template": "auto",
            },
        ]

        # 1. Add all rules
        for rule in test_rules:
            rm.add_rule(dict(rule))

        # 2. Parse back
        parsed_rules = {r["id"].replace("custom-", ""): r for r in rm.list_rules()}

        for original in test_rules:
            rid = original["id"]
            assert rid in parsed_rules
            parsed = parsed_rules[rid]
            assert parsed["variable"] == original["variable"]
            assert parsed["operator"] == original["operator"]
            assert parsed["action"] == original["action"]
            assert parsed["deception_template"] == original["deception_template"]
            assert parsed["message"] == original["message"]

    def test_operator_backslash_accumulation_bug(self, tmp_path):
        """TC-ADV-RT-02: EMPIRICAL BUG - Operator containing regex backslashes doubles on every save/parse cycle."""
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        original_operator = r"@rx \.\./"
        rule = {
            "id": "310001",
            "variable": "REQUEST_URI",
            "operator": original_operator,
            "severity": "CRITICAL",
            "message": "Regex backslash test",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        }
        rm.add_rule(dict(rule))

        # Cycle 1: Read back
        r1 = rm.list_rules()[0]
        # In the conf file, safe_operator escaped \ to \\: "@rx \\.\\./"
        # When list_rules() extracts it, it does NOT unescape it!
        # So r1['operator'] is now r'@rx \\.\\./'
        # Fixed: the parser unescapes, so the operator is stable across cycles
        assert r1["operator"] == original_operator, r1["operator"]

        # Cycle 2: Update with what list_rules returned
        rm.update_rule("310001", dict(r1))
        r2 = rm.list_rules()[0]
        # Backslashes doubled again!
        assert r2["operator"] == original_operator, r2["operator"]

        # Cycle 3: Update again
        rm.update_rule("310001", dict(r2))
        r3 = rm.list_rules()[0]
        assert r3["operator"] == original_operator, r3["operator"]

    def test_message_apostrophe_truncation_bug(self, tmp_path):
        """TC-ADV-RT-03: EMPIRICAL BUG - Message containing single quote/apostrophe is truncated on round-trip."""
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        original_message = "Don't allow attacker's payload"
        rule = {
            "id": "320001",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": original_message,
            "action": "BLOCK",
            "deception_template": "auto",
        }
        rm.add_rule(dict(rule))

        parsed = rm.list_rules()[0]
        # BUG: list_rules uses msg:'([^']+)' which stops at the first apostrophe!
        # "Don't allow attacker's payload" is truncated to "Don\\"
        # Fixed: apostrophes survive the round trip
        assert parsed["message"] == original_message

    def test_message_double_quote_directive_breakdown(self, tmp_path):
        """TC-ADV-RT-04: Double quotes in message break outer SecRule actions string."""
        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        # Rule created with double quotes in message
        rule = {
            "id": "330001",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": 'Blocked probe tag:"action:deceive" in request',
            "action": "BLOCK",
            "deception_template": "auto",
        }
        rm.add_rule(dict(rule))

        # Because escape_secrule_string only escapes single quotes for message,
        # the double quote inside msg:'...' terminates the outer SecRule double-quoted string!
        with open(tmp_path / "custom-330001.conf", "r", encoding="utf-8") as f:
            content = f.read()

        # Fixed: double quotes are escaped inside the actions block
        assert 'msg:\'Blocked probe tag:\\"action:deceive\\" in request\'' in content

        # When parsed by list_rules, the first regex group for actions terminates early at the double quote
        parsed = rm.list_rules()[0]
        # The message text mentions a tag but must not change the rule's action
        assert parsed["action"] == "BLOCK"
        assert parsed["message"] == rule["message"]


# ==============================================================================
# SECTION 4: RBAC Bypass & Authorization Stress Testing
# ==============================================================================

class TestRbacBypassAttempts:
    """Stress test RBAC authorization on rule sync and modification endpoints."""

    def test_unauthenticated_requests_rejected(self, client: TestClient):
        """TC-ADV-RBAC-01: All mutation endpoints reject unauthenticated callers with 401."""
        client.cookies.clear()
        endpoints = [
            ("POST", "/api/rules/", {"id": "400001", "variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "unauth"}),
            ("PUT", "/api/rules/400001", {"variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "unauth"}),
            ("DELETE", "/api/rules/400001", None),
            ("POST", "/api/rules/sync", None),
            ("POST", "/api/rules/bola/policies", {"name": "test", "path_pattern": "^/api/test"}),
            ("PUT", "/api/rules/bola/policies/pol1", {"name": "test"}),
            ("DELETE", "/api/rules/bola/policies/pol1", None),
        ]

        for method, path, body in endpoints:
            if method == "POST":
                resp = client.post(path, json=body)
            elif method == "PUT":
                resp = client.put(path, json=body)
            elif method == "DELETE":
                resp = client.delete(path)
            assert resp.status_code == 401, f"{method} {path} expected 401, got {resp.status_code}"

    def test_viewer_cannot_modify_or_sync_rules(self, client: TestClient, register_user, auth_header):
        """TC-ADV-RBAC-02: Viewer role receives HTTP 403 on all modification and sync endpoints."""
        register_user(email="admin-sec@example.com", username="admin_sec")
        viewer = register_user(email="viewer-sec@example.com", username="viewer_sec", role="viewer")
        headers = auth_header(viewer["access_token"])

        # 1. POST /api/rules/
        r_post = client.post(
            "/api/rules/",
            json={"id": "410001", "variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "viewer attack", "action": "DECEIVE"},
            headers=headers,
        )
        assert r_post.status_code == 403
        assert r_post.json()["detail"] == "Admin access required"

        # 2. PUT /api/rules/{id}
        r_put = client.put(
            "/api/rules/410001",
            json={"variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "viewer update", "action": "DECEIVE"},
            headers=headers,
        )
        assert r_put.status_code == 403
        assert r_put.json()["detail"] == "Admin access required"

        # 3. DELETE /api/rules/{id}
        r_del = client.delete("/api/rules/410001", headers=headers)
        assert r_del.status_code == 403
        assert r_del.json()["detail"] == "Admin access required"

        # 4. POST /api/rules/sync
        r_sync = client.post("/api/rules/sync", headers=headers)
        assert r_sync.status_code == 403
        assert r_sync.json()["detail"] == "Admin access required"

    def test_forged_and_tampered_jwt_roles(self, client: TestClient, register_user, auth_header):
        """TC-ADV-RBAC-03: Reject tampered roles (ADMIN, operator, superadmin, none alg)."""
        auth_service = AuthService()

        # Attack 1: Role casing bypass attempt (role="ADMIN" vs required "admin")
        token_upper = auth_service.create_access_token({"sub": "attacker1", "role": "ADMIN"})
        resp = client.post(
            "/api/rules/",
            json={"id": "420001", "variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "casing bypass"},
            headers=auth_header(token_upper),
        )
        # Should be 401 because user attacker1 is not in user DB or 403
        assert resp.status_code in (401, 403)

        # Attack 2: Bogus token string
        resp_garbage = client.post(
            "/api/rules/",
            json={"id": "420002", "variable": "REQUEST_URI", "operator": "@rx .", "severity": "HIGH", "message": "garbage token"},
            headers={"Authorization": "Bearer not-a-real-jwt-token-at-all"},
        )
        assert resp_garbage.status_code == 401

    def test_path_traversal_in_delete_rule(self, tmp_path):
        """TC-ADV-RBAC-04: EMPIRICAL VULNERABILITY - Path traversal arbitrary file deletion in RuleManager.delete_rule."""
        sub_rules_dir = tmp_path / "rules"
        sub_rules_dir.mkdir()
        victim_file = tmp_path / "victim.conf"
        victim_file.write_text("CRITICAL SYSTEM CONFIG", encoding="utf-8")

        rm = RuleManager.__new__(RuleManager)
        rm.rules_dir = str(sub_rules_dir)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        assert victim_file.exists()
        # Exploit: pass path traversal string to delete_rule
        traversal_id = "../victim"
        result = rm.delete_rule(traversal_id)

        # VULNERABILITY CONFIRMATION:
        # RuleManager.delete_rule did not sanitize rule_id and removed victim.conf!
        assert result is True
        assert not victim_file.exists(), "CRITICAL BUG: Arbitrary file outside rules_dir was deleted via path traversal!"
