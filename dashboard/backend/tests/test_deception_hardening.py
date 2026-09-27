"""Regression tests for the 2026-09-27 deception-layer review findings."""
import os

import pytest

from api import rules as rules_module
from services import deception_service as deception_module
from services.deception_service import DeceptionLogEvent, DeceptionService

os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")


def _rule(**over):
    rule = {
        "id": "700001",
        "variable": "REQUEST_URI",
        "operator": "@contains trap",
        "severity": "CRITICAL",
        "message": "Trap",
        "action": "DECEIVE",
        "deception_template": "auto",
    }
    rule.update(over)
    return rule


@pytest.mark.parametrize("field", ["operator", "message"])
@pytest.mark.parametrize("bad", ["a\nSecRuleEngine Off", "a\rb", "a\x00b"])
def test_control_characters_rejected(field, bad):
    ok, _ = rules_module.rule_manager.validate_rule(_rule(**{field: bad}))
    assert not ok


def test_deceive_on_request_body_rejected():
    ok, msg = rules_module.rule_manager.validate_rule(_rule(variable="REQUEST_BODY"))
    assert not ok and "REQUEST_BODY" in msg


def test_message_double_quote_cannot_close_action_list(tmp_path):
    rm = rules_module.rule_manager
    rm.add_rule(_rule(message='x" ,ctl:ruleEngine=Off,"'))
    text = (tmp_path / "custom-700001.conf").read_text()
    action_line = text.splitlines()[-1]
    # the only unescaped double quotes are the two that wrap the action list
    unescaped = [i for i, c in enumerate(action_line) if c == '"' and action_line[i - 1] != "\\"]
    assert len(unescaped) == 2


def test_failed_update_restores_previous_rule(tmp_path, monkeypatch):
    rm = rules_module.rule_manager
    rm.add_rule(_rule())
    path = tmp_path / "custom-700001.conf"
    before = path.read_text()

    def broken():
        raise RuntimeError("nginx -t failed")

    monkeypatch.setattr(rm, "test_nginx", broken)
    with pytest.raises(RuntimeError):
        rm.update_rule("700001", _rule(message="changed"))
    assert path.read_text() == before


def test_host_is_logged_for_tenant_attribution():
    saved = {}

    class CH:
        connected = True
        client = None

        def save_log(self, table, entry):
            saved.setdefault(table, entry)
            return True

    svc = DeceptionService(ch_service=CH(), db_service=None)
    svc._db = None
    event = DeceptionLogEvent(
        request_id="r1", timestamp=0, rule_id="9000000", attack_category="LFI",
        template_id="path_traversal", response_status=200, execution_result="deceived",
        client_ip="8.8.8.8", method="GET", url="/x", user_agent="ua", edge_node="edge-th",
        latency_ms=1.0, body_bytes_sent=1, datetime="2026-09-27T00:00:00Z", host="shop.example.com",
    )
    svc.log_deception_event(event)
    assert saved["access_logs"]["host"] == "shop.example.com"
    assert "country" not in saved["access_logs"]  # derived from the IP by save_log


def test_unterminated_comment_is_not_quadratic():
    import time

    payload = "/*" * 2048
    start = time.perf_counter()
    deception_module.SQLI_REGEX.search(payload)
    assert time.perf_counter() - start < 0.05


def test_respond_forwards_original_host():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api import deception as deception_api

    app = FastAPI()
    app.include_router(deception_api.router)
    client = TestClient(app)
    captured = {}
    original = deception_module.deception_service.log_deception_event
    deception_module.deception_service.log_deception_event = lambda e: captured.setdefault("e", e)
    try:
        r = client.get(
            "/api/deception/respond",
            headers={
                "X-Internal-Deception-Key": os.environ["DECEPTION_INTERNAL_KEY"],
                "X-Original-URI": "/?deceive_me_lfi",
                "X-Original-Host": "shop.example.com",
            },
        )
    finally:
        deception_module.deception_service.log_deception_event = original
    assert r.status_code == 200
    assert captured["e"].host == "shop.example.com"
