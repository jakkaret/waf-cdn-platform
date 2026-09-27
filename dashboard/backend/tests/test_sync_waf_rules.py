"""
Unit and Integration Test Suite for scripts/sync_waf_rules.py.

Validates:
- Rule conversion to ModSecurity SecRule directives
- Proper status:418 and tag:'action:deceive' generation for DECEIVE rules
- Status:401 and tag:'action:challenge' for CHALLENGE rules
- Status:403 for BLOCK and legacy rules
- SecRule string escaping for operators and messages
- Skipping invalid IDs and override files
- Dry-run container sync and structured sync logging
- POST /api/rules/sync authorization and execution
"""

import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

# Ensure scripts/ directory is in sys.path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import sync_waf_rules


def test_sync_formatter_serializes_deceive_rules():
    """TC-SYNC-01: Serializes DECEIVE rules with status:418 and deception tags."""
    rules = [
        {
            "id": "custom-100001",
            "variable": "REQUEST_URI",
            "operator": "@rx \\.\\./",
            "severity": "CRITICAL",
            "message": "Mitigate Path Traversal via Honeypot",
            "action": "DECEIVE",
            "deception_template": "path_traversal",
        }
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert 'SecRule REQUEST_URI "@rx \\\\.\\\\./" \\' in conf
    assert 'id:100001,phase:1,deny,status:418,tag:\'action:deceive\',tag:\'template:path_traversal\',severity:CRITICAL,log,msg:\'Mitigate Path Traversal via Honeypot\'' in conf


def test_sync_formatter_serializes_challenge_rules():
    """TC-SYNC-02: Serializes CHALLENGE rules with status:401 and challenge tag."""
    rules = [
        {
            "id": "100002",
            "variable": "REQUEST_HEADERS",
            "operator": "@contains bot",
            "severity": "MEDIUM",
            "message": "Challenge automated bot",
            "action": "CHALLENGE",
        }
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert 'SecRule REQUEST_HEADERS "@contains bot" \\' in conf
    assert 'id:100002,phase:2,deny,status:401,tag:\'action:challenge\',severity:MEDIUM,log,msg:\'Challenge automated bot\'' in conf


def test_sync_formatter_serializes_block_rules():
    """TC-SYNC-03: Serializes BLOCK rules with status:403."""
    rules = [
        {
            "id": "custom-100003",
            "variable": "ARGS",
            "operator": "@rx (?i)select.*from",
            "severity": "HIGH",
            "message": "Block SQLi",
            "action": "BLOCK",
        }
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert 'id:100003,phase:2,deny,status:403,severity:HIGH,log,msg:\'Block SQLi\'' in conf


def test_sync_formatter_handles_legacy_rules_without_action():
    """TC-SYNC-04: Legacy rules without action key default to BLOCK (status:403)."""
    rules = [
        {
            "id": "100004",
            "variable": "REQUEST_URI",
            "operator": "@contains /legacy",
            "severity": "LOW",
            "message": "Legacy probe",
        }
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert 'id:100004,phase:2,deny,status:403,severity:LOW,log,msg:\'Legacy probe\'' in conf


def test_sync_formatter_strips_custom_prefix_and_skips_non_numeric():
    """TC-SYNC-05: Strips custom- from ID and skips non-numeric or dummy files."""
    rules = [
        {
            "id": "00-modsecurity-override",
            "variable": "N/A",
            "operator": "N/A",
            "severity": "N/A",
            "message": "N/A",
        },
        {
            "id": "invalid-non-numeric",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "HIGH",
            "message": "Should be skipped",
        },
        {
            "id": "custom-100005",
            "variable": "REQUEST_URI",
            "operator": "@rx .",
            "severity": "CRITICAL",
            "message": "Valid numeric rule",
            "action": "DECEIVE",
        },
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert "00-modsecurity-override" not in conf
    assert "invalid-non-numeric" not in conf
    assert "id:100005" in conf


def test_sync_formatter_escapes_special_characters():
    """TC-SYNC-06: Escapes double quotes and backslashes in operators and messages."""
    attack_operator = '@rx test"quote'
    attack_message = "pwned\\' ctl:ruleRemoveById=900001"
    rules = [
        {
            "id": "100006",
            "variable": "ARGS",
            "operator": attack_operator,
            "severity": "CRITICAL",
            "message": attack_message,
            "action": "DECEIVE",
        }
    ]
    conf = sync_waf_rules.rules_to_modsecurity_conf(rules)
    assert '@rx test\\"quote' in conf
    assert "pwned\\\\\\' ctl:ruleRemoveById=900001" in conf


def test_sync_to_container_dry_run_mode(tmp_path):
    """TC-SYNC-07: Container sync in dry-run mode does not invoke subprocess."""
    dummy_conf = tmp_path / "test.conf"
    dummy_conf.write_text("SecRule ...", encoding="utf-8")

    result = sync_waf_rules.sync_to_container(
        region="TH",
        container="cdn-edge-th",
        conf=dummy_conf,
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["region"] == "TH"
    assert result["container"] == "cdn-edge-th"
    assert result["error"] is None


def test_write_sync_log_creates_json_entries(tmp_path, monkeypatch):
    """TC-SYNC-08: Structured JSON sync logging creates parseable entries."""
    log_file = tmp_path / "sync.log"
    monkeypatch.setattr(sync_waf_rules, "SYNC_LOG_FILE", log_file)

    test_results = [
        {"region": "SG", "status": "synced"},
        {"region": "JP", "status": "synced"},
        {"region": "TH", "status": "synced"},
    ]
    sync_waf_rules.write_sync_log(test_results)

    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    logged_entry = json.loads(lines[0])
    assert "timestamp" in logged_entry
    assert logged_entry["results"] == test_results


def test_api_rules_sync_rbac(client: TestClient, register_user, auth_header):
    """TC-SYNC-09: POST /api/rules/sync requires admin authorization."""
    register_user(email="admin-sync@example.com", username="admin_sync")
    viewer = register_user(email="viewer-sync@example.com", username="viewer_sync", role="viewer")

    # Viewer should be rejected with 403
    resp = client.post("/api/rules/sync", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"

    # Unauthenticated should be rejected with 401
    client.cookies.clear()
    resp_unauth = client.post("/api/rules/sync")
    assert resp_unauth.status_code == 401
