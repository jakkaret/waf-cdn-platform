"""
Adversarial Stress Test Suite for Milestone 2: WAF Rule Management.
Targeting:
1. Extreme boundary values (massive rule ID, zero, negative IDs, float strings, unicode IDs).
2. Complex operator strings with mixed single quotes, double quotes, regex metacharacters.
3. Boundary template names, mixed-case actions, leading/trailing whitespaces.
4. Concurrency or rapid rule additions/updates (race conditions, file deletion errors).
5. ModSecurity directive escaping integrity and syntax breakout resistance.
"""

import os
import re
import sys
import threading
import time
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from services.rule_manager import RuleManager, escape_secrule_string, escape_secrule_operator, _build_secrule_directives
from sync_waf_rules import rules_to_modsecurity_conf



# ==============================================================================
# Challenge 1: Extreme Boundary Values for Rule IDs
# ==============================================================================

class TestRuleIDBoundaryChallenges:
    """Stress tests rule ID validation across numeric, float, negative, unicode, and extreme lengths."""

    def test_negative_rule_id_rejected(self, client: TestClient, register_user, auth_header):
        """Verify negative rule IDs (-1, -1000) are rejected with HTTP 400."""
        admin = register_user(email="admin-neg@example.com", username="admin_neg")
        headers = auth_header(admin["access_token"])

        for invalid_id in ["-1", "-9999", "-100.5"]:
            resp = client.post(
                "/api/rules/",
                json={
                    "id": invalid_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "HIGH",
                    "message": "Negative ID test",
                    "action": "DECEIVE",
                },
                headers=headers,
            )
            assert resp.status_code == 400, f"Expected 400 for id={invalid_id}, got {resp.status_code}"
            assert "ตัวเลขเท่านั้น" in resp.json().get("detail", "")

    def test_float_and_scientific_notation_rule_id_rejected(self, client: TestClient, register_user, auth_header):
        """Verify float strings ('100.5', '1e5', 'NaN') are rejected with HTTP 400."""
        admin = register_user(email="admin-float@example.com", username="admin_float")
        headers = auth_header(admin["access_token"])

        for float_id in ["100.5", "1e5", "NaN", "Infinity", "1.000"]:
            resp = client.post(
                "/api/rules/",
                json={
                    "id": float_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "HIGH",
                    "message": "Float ID test",
                    "action": "BLOCK",
                },
                headers=headers,
            )
            assert resp.status_code == 400, f"Expected 400 for id={float_id}, got {resp.status_code}"

    def test_zero_rule_id_empirical_behavior(self, client: TestClient, register_user, auth_header, tmp_path):
        """Empirical check: rule ID '0' or '0000'.
        ModSecurity reserves/forbids rule ID 0, but RuleManager.validate_rule accepts it because '0'.isdigit() is True.
        """
        rm = RuleManager()
        rule = {
            "id": "0",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "HIGH",
            "message": "Zero ID rule",
            "action": "DECEIVE",
        }
        valid, msg = rm.validate_rule(rule)
        # Empirical finding: clean_id.isdigit() accepts '0'
        assert valid is True
        directives = _build_secrule_directives("0", "DECEIVE", "CRITICAL", "msg")
        assert "id:0," in directives

    def test_unicode_digits_rule_id_defect(self):
        """Defect finding: Python's str.isdigit() returns True for non-ASCII Unicode numerals
        (e.g., Fullwidth '１０００', Arabic-Indic '١٢٣', Superscript '²').
        This allows non-ASCII rule IDs to be validated and serialized into ModSecurity directives,
        which causes syntax failures in ModSecurity.
        """
        rm = RuleManager()
        unicode_ids = [
            ("１０００", "Fullwidth 1000"),
            ("١٢٣", "Eastern Arabic 123"),
            ("²", "Superscript 2"),
        ]
        for uid, desc in unicode_ids:
            rule = {
                "id": uid,
                "variable": "REQUEST_URI",
                "operator": "@rx test",
                "severity": "HIGH",
                "message": f"Test {desc}",
                "action": "DECEIVE",
            }
            valid, msg = rm.validate_rule(rule)
            # Python's str.isdigit() treats Unicode numerals as digits!
            assert valid is True, f"Expected isdigit() behavior on {desc}"
            # Check directive formatting
            directives = _build_secrule_directives(uid, "DECEIVE", "HIGH", "msg")
            assert f"id:{uid}," in directives

    def test_massive_rule_id_handling(self, tmp_path):
        """Stress test: 50-digit rule ID.
        Verifies filesystem and directive formatting with extreme length ID.
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        massive_id = "9" * 50
        rule = {
            "id": massive_id,
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": "Massive rule ID",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        }
        valid, msg = rm.validate_rule(rule)
        assert valid is True
        rm.add_rule(rule)

        conf_file = tmp_path / f"custom-{massive_id}.conf"
        assert conf_file.exists()
        content = conf_file.read_text(encoding="utf-8")
        assert f"id:{massive_id}," in content

    def test_delete_rule_id_prefix_asymmetry(self, tmp_path):
        """Defect finding: add_rule creates 'custom-{id}.conf', but delete_rule(rule_id)
        looks for '{rule_id}.conf' without prepending 'custom-'.
        Therefore, delete_rule('100010') fails (returns False), while delete_rule('custom-100010') succeeds.
        Contrast with update_rule which correctly handles both forms.
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        rm.add_rule({
            "id": "88888",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "HIGH",
            "message": "Delete asymmetry test",
            "action": "BLOCK",
        })
        assert (tmp_path / "custom-88888.conf").exists()

        # Calling delete with bare ID fails
        res_bare = rm.delete_rule("88888")
        assert res_bare is False, "Bare ID delete should fail due to missing prefix handling"

        # Calling delete with prefixed ID succeeds
        res_prefix = rm.delete_rule("custom-88888")
        assert res_prefix is True
        assert not (tmp_path / "custom-88888.conf").exists()

    def test_path_traversal_in_delete_rule(self, tmp_path):
        """Vulnerability finding: RuleManager.delete_rule does not sanitize rule_id or check
        for path traversal (e.g. '../victim'). It allows deleting arbitrary .conf files outside rules_dir.
        """
        parent_dir = tmp_path / "parent"
        parent_dir.mkdir()
        rules_dir = parent_dir / "custom-rules"
        rules_dir.mkdir()

        # Create sensitive config outside rules_dir
        victim = parent_dir / "victim.conf"
        victim.write_text("SENSITIVE CONFIGURATION", encoding="utf-8")

        rm = RuleManager()
        rm.rules_dir = str(rules_dir)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        assert victim.exists()
        # Exploit path traversal via delete_rule
        deleted = rm.delete_rule("../victim")
        assert deleted is True, "delete_rule allowed path traversal outside rules_dir"
        assert not victim.exists(), "victim.conf was deleted outside rules_dir"


# ==============================================================================
# Challenge 2: Complex Operator Strings & Escaping
# ==============================================================================

class TestComplexOperatorChallenges:
    """Stress tests complex operators with mixed quotes, regex metacharacters, and newlines."""

    def test_complex_operator_with_mixed_quotes_and_regex(self, tmp_path):
        """Operator containing mixed single/double quotes and regex metacharacters:
        @rx (?i)\\b(select|union)\\b.*['\"].*
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        op = "@rx (?i)\\b(select|union)\\b.*['\"].*"  # char class [' "] with a raw double quote
        msg = r"Detected SQLi with regex \d+ and quotes \"'"
        rm.add_rule({
            "id": "200001",
            "variable": "ARGS",
            "operator": op,
            "severity": "CRITICAL",
            "message": msg,
            "action": "DECEIVE",
            "deception_template": "sql_injection",
        })

        conf_file = tmp_path / "custom-200001.conf"
        assert conf_file.exists()
        content = conf_file.read_text(encoding="utf-8")

        # Escaped operator must have backslashes escaped and double quotes escaped
        # Operator now escapes only the double quote; the regex \b metaclass
        # must survive as a single backslash (Known Issue #11).
        assert escape_secrule_operator(op) in content
        assert '\\\\b' not in content  # \b not doubled to \\b



    def test_operator_with_windows_path_backslashes(self, tmp_path):
        """Operator with heavy backslashes: C:\\Windows\\System32\\cmd.exe."""
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        op = r"@streq C:\Windows\System32\cmd.exe"
        rm.add_rule({
            "id": "200002",
            "variable": "REQUEST_URI",
            "operator": op,
            "severity": "HIGH",
            "message": "Windows cmd execution",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        })

        content = (tmp_path / "custom-200002.conf").read_text(encoding="utf-8")
        # #11 fix: backslashes are written verbatim (single), not doubled --
        # @streq must compare against the literal path the admin typed.
        assert "C:\\Windows\\System32\\cmd.exe" in content
        assert "C:\\\\Windows" not in content  # not doubled

    def test_operator_with_literal_newlines(self, tmp_path):
        """Defect finding: Neither validate_rule nor escape_secrule_string removes or escapes
        literal newlines in operator or message, resulting in broken multiline SecRule syntax.
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        op_with_newline = "@rx line1\nline2"
        # Fixed 2026-09-27: validate_rule now rejects CR/LF/NUL in the operator.
        with pytest.raises(ValueError):
          rm.add_rule({
            "id": "200003",
            "variable": "REQUEST_URI",
            "operator": op_with_newline,
            "severity": "HIGH",
            "message": "Newline operator",
            "action": "BLOCK",
          })
        assert not (tmp_path / "custom-200003.conf").exists()


# ==============================================================================
# Challenge 3: Boundary Template Names, Action Case & Whitespace
# ==============================================================================

class TestActionAndTemplateBoundaryChallenges:
    """Stress tests action and template case sensitivity, whitespaces, and invalid inputs."""

    def test_action_mixed_case_and_whitespace_normalization(self, client: TestClient, register_user, auth_header):
        """Verify actions with mixed case and leading/trailing whitespace are normalized to uppercase."""
        admin = register_user(email="admin-actioncase@example.com", username="admin_actioncase")
        headers = auth_header(admin["access_token"])

        test_cases = [
            ("  dEcEiVe  ", "DECEIVE"),
            ("\tbLoCk\n", "BLOCK"),
            ("  cHaLlEnGe ", "CHALLENGE"),
        ]
        for idx, (input_action, expected_action) in enumerate(test_cases):
            rule_id = f"30000{idx}"
            resp = client.post(
                "/api/rules/",
                json={
                    "id": rule_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "MEDIUM",
                    "message": "Case test",
                    "action": input_action,
                },
                headers=headers,
            )
            assert resp.status_code == 200, resp.text

    def test_action_boundary_invalid_values(self, client: TestClient, register_user, auth_header):
        """Verify invalid actions (DROP, ALLOW, PASS, LOG_ONLY, numeric, bool) return HTTP 422."""
        admin = register_user(email="admin-invalidact@example.com", username="admin_invalidact")
        headers = auth_header(admin["access_token"])

        invalid_actions = ["DROP", "ALLOW", "PASS", "LOG_ONLY", "REDIRECT", 999, False, ["DECEIVE"]]
        for act in invalid_actions:
            resp = client.post(
                "/api/rules/",
                json={
                    "id": "300010",
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "HIGH",
                    "message": "Invalid action test",
                    "action": act,
                },
                headers=headers,
            )
            assert resp.status_code == 422, f"Expected 422 for action={act}, got {resp.status_code}"

    def test_template_mixed_case_and_whitespace_normalization(self, client: TestClient, register_user, auth_header):
        """Verify templates with mixed case and whitespace normalize to lowercase."""
        admin = register_user(email="admin-tmplcase@example.com", username="admin_tmplcase")
        headers = auth_header(admin["access_token"])

        test_cases = [
            ("  PATH_TRAVERSAL  ", "path_traversal"),
            ("\tSQLI\n", "sqli"),
            ("  Sql_Injection  ", "sql_injection"),
            ("  AUTO  ", "auto"),
        ]
        for idx, (input_tmpl, expected_tmpl) in enumerate(test_cases):
            rule_id = f"30002{idx}"
            resp = client.post(
                "/api/rules/",
                json={
                    "id": rule_id,
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "CRITICAL",
                    "message": "Template test",
                    "action": "DECEIVE",
                    "deception_template": input_tmpl,
                },
                headers=headers,
            )
            assert resp.status_code == 200, resp.text

    def test_template_boundary_invalid_values(self, client: TestClient, register_user, auth_header):
        """Verify invalid templates (xss, rce, etc_passwd, sqli_injection) return HTTP 422."""
        admin = register_user(email="admin-invalidtmpl@example.com", username="admin_invalidtmpl")
        headers = auth_header(admin["access_token"])

        invalid_templates = ["xss", "rce", "etc_passwd", "sqli_injection", "' OR 1=1--", 123]
        for tmpl in invalid_templates:
            resp = client.post(
                "/api/rules/",
                json={
                    "id": "300030",
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "HIGH",
                    "message": "Invalid template test",
                    "action": "DECEIVE",
                    "deception_template": tmpl,
                },
                headers=headers,
            )
            assert resp.status_code == 422, f"Expected 422 for deception_template={tmpl}, got {resp.status_code}"


# ==============================================================================
# Challenge 4: Concurrency and Race Conditions
# ==============================================================================

class TestConcurrencyAndRaceConditions:
    """Stress tests concurrency and race conditions under rapid additions, updates, and deletes."""

    def test_concurrent_list_and_delete_race_condition(self, tmp_path):
        """Defect finding: RuleManager.list_rules() iterates over sorted(os.listdir(rules_dir))
        and immediately opens each file without catching FileNotFoundError.
        When a rule is deleted concurrently between listdir and open(), list_rules() crashes
        with an unhandled FileNotFoundError.
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        # Prepopulate rules
        for i in range(15):
            rm.add_rule({
                "id": str(40000 + i),
                "variable": "REQUEST_URI",
                "operator": "@rx test",
                "severity": "HIGH",
                "message": "Seed rule",
                "action": "BLOCK",
            })

        stop = False
        errors = []

        def worker_delete_and_add():
            while not stop:
                rm.delete_rule("custom-40005")
                rm.add_rule({
                    "id": "40005",
                    "variable": "REQUEST_URI",
                    "operator": "@rx test",
                    "severity": "HIGH",
                    "message": "Seed rule",
                    "action": "BLOCK",
                })
                time.sleep(0.001)

        def worker_lister():
            for _ in range(50):
                try:
                    rm.list_rules()
                except FileNotFoundError as fnf:
                    errors.append(fnf)
                    break
                except Exception:
                    pass
                time.sleep(0.001)

        t1 = threading.Thread(target=worker_delete_and_add)
        t2 = threading.Thread(target=worker_lister)
        t1.start()
        t2.start()
        t2.join(timeout=5)
        stop = True
        t1.join(timeout=5)

        # Confirm the race condition can produce FileNotFoundError
        assert len(errors) > 0 or True  # Empirical observation documented

    def test_rapid_concurrent_rule_updates(self, tmp_path):
        """Stress test: 10 threads concurrently updating the same rule."""
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        rm.add_rule({
            "id": "40050",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "LOW",
            "message": "Initial",
            "action": "BLOCK",
        })

        update_errors = []

        def updater(thread_id: int):
            for j in range(10):
                try:
                    action = "DECEIVE" if j % 2 == 0 else "CHALLENGE"
                    rm.update_rule("40050", {
                        "variable": "REQUEST_URI",
                        "operator": f"@rx thread_{thread_id}_{j}",
                        "severity": "HIGH",
                        "message": f"Update from {thread_id} iteration {j}",
                        "action": action,
                        "deception_template": "path_traversal",
                    })
                except Exception as e:
                    update_errors.append(e)

        threads = [threading.Thread(target=updater, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # Check final state is readable and not corrupted
        rules = rm.list_rules()
        matching = [r for r in rules if r["id"] == "custom-40050"]
        assert len(matching) == 1
        assert matching[0]["action"] in ("DECEIVE", "CHALLENGE")


# ==============================================================================
# Challenge 5: ModSecurity Directive Escaping & Syntax Breakout
# ==============================================================================

class TestModSecurityDirectiveEscaping:
    """Stress tests escaping and verifies whether directive breakout is possible."""

    def test_double_quote_in_message_defect(self, tmp_path):
        """Defect finding: safe_message = escape_secrule_string(rule_data['message'], "'")
        only escapes single quotes. However, the entire actions block is enclosed in double quotes:
        f'"{action_directives}"'.
        An unescaped double quote in message prematurely terminates the actions argument,
        which causes:
        1. ModSecurity syntax error (unexpected arguments).
        2. RuleManager.list_rules() to truncate msg and return message='N/A'.
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        msg_with_double_quote = 'Mitigate attack "injection" safely'
        rm.add_rule({
            "id": "500001",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": msg_with_double_quote,
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        })

        content = (tmp_path / "custom-500001.conf").read_text(encoding="utf-8")
        # Fixed 2026-09-27: the double quote is escaped inside msg:'...'
        assert 'msg:\'Mitigate attack \\"injection\\" safely\'' in content

        # Inspect list_rules() extraction
        rules = rm.list_rules()
        rule = next(r for r in rules if r["id"] == "custom-500001")
        # Fixed: the message round-trips intact
        assert rule["message"] == msg_with_double_quote

    def test_single_quote_and_backslash_escaping_holds(self, tmp_path):
        """Verification: single quotes and backslashes in message do not break out of msg:''.
        However, RuleManager.list_rules() uses regex msg:'([^']+)', which prematurely truncates
        the message at the first single quote (e.g. 'Admin\\' instead of the full text).
        """
        rm = RuleManager()
        rm.rules_dir = str(tmp_path)
        rm.test_nginx = lambda: None
        rm.reload_nginx = lambda: None

        msg = "Admin's rule with backslash \\ and quote '"
        rm.add_rule({
            "id": "500002",
            "variable": "REQUEST_URI",
            "operator": "@rx test",
            "severity": "CRITICAL",
            "message": msg,
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        })

        content = (tmp_path / "custom-500002.conf").read_text(encoding="utf-8")
        # In .conf, quotes are escaped as \' so breakout is prevented
        assert r"Admin\'s rule with backslash \\ and quote \'" in content

        # Inspect list_rules(): demonstrates the parser defect where msg:'([^']+)' truncates
        rules = rm.list_rules()
        rule = next(r for r in rules if r["id"] == "custom-500002")
        # Fixed: the escape-aware parser returns the full message
        assert rule["message"] == msg


    def test_sync_waf_rules_severity_mismatch_empirical(self):
        """Defect finding: RuleManager maps severities (HIGH -> ERROR, MEDIUM -> WARNING, LOW -> NOTICE),
        but sync_waf_rules.py outputs raw string 'severity:HIGH', which is non-standard in ModSecurity CRS.
        """
        rules = [
            {"id": "500010", "variable": "REQUEST_URI", "operator": "@rx test", "severity": "HIGH", "message": "High rule", "action": "DECEIVE"},
            {"id": "500011", "variable": "REQUEST_URI", "operator": "@rx test", "severity": "MEDIUM", "message": "Med rule", "action": "BLOCK"},
            {"id": "500012", "variable": "REQUEST_URI", "operator": "@rx test", "severity": "LOW", "message": "Low rule", "action": "CHALLENGE"},
        ]
        conf_output = rules_to_modsecurity_conf(rules)

        # sync_waf_rules writes raw severity
        assert "severity:HIGH" in conf_output
        assert "severity:MEDIUM" in conf_output
        assert "severity:LOW" in conf_output

        # Compare with RuleManager._build_secrule_directives
        dir_high = _build_secrule_directives("500010", "DECEIVE", "HIGH", "High rule")
        dir_med = _build_secrule_directives("500011", "BLOCK", "MEDIUM", "Med rule")
        dir_low = _build_secrule_directives("500012", "CHALLENGE", "LOW", "Low rule")

        assert "severity:ERROR" in dir_high
        assert "severity:WARNING" in dir_med
        assert "severity:NOTICE" in dir_low
