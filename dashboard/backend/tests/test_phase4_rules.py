"""Phase 4 of the remediation plan (security audit run 1): the WAF rule
pipeline -- generated rules are checked before they reach nginx, the rules
API deletes only custom rules, every rule writer shares one lock, and the
settings and log-ingest inputs are validated."""
import asyncio
import re
import threading
import time

import pytest
from fastapi import HTTPException

from services import rule_manager as rm_module
from services.rule_manager import RuleManager, validate_ml_rule_text

GOOD = '''SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)union\\s+select" \\
    "id:1000600,\\
    phase:2,\\
    deny,\\
    status:403,\\
    severity:CRITICAL,\\
    log,\\
    msg:'ML Auto-Generated WAF Rule: Blocked SQLi Pattern'"'''


# --------------------------------------------- P4.2 generated rules are checked

def test_a_normal_generated_rule_passes():
    validate_ml_rule_text(GOOD, 1000600)


@pytest.mark.parametrize("text, why", [
    (GOOD + "\nSecRule ARGS \"@rx x\" \"id:1000601,phase:2,deny\"", "two rules"),
    (GOOD.replace("id:1000600", "id:1000999"), "another id"),
    (GOOD.replace("deny,", "deny,ctl:ruleEngine=Off,"), "ctl"),
    (GOOD.replace("deny,", "pass,"), "pass instead of deny"),
    (GOOD.replace("deny,", "deny,exec:/tmp/x.sh,"), "exec"),
    (GOOD.replace("deny,", "deny,chain,"), "chain"),
    (GOOD + "\nSecRuleEngine Off", "extra directive"),
    (GOOD + "\nInclude /etc/passwd", "include"),
    (GOOD.replace("phase:2", "phase:5"), "logging phase"),
    (GOOD.replace("Blocked", "Blocked\x0b"), "control character"),
    ("SecAction \"id:1000600,phase:1,deny\"", "not a SecRule"),
])
def test_a_generated_rule_outside_the_allowed_shape_is_refused(text, why):
    with pytest.raises(ValueError):
        validate_ml_rule_text(text, 1000600)


def test_write_ml_rule_refuses_before_writing(tmp_path):
    rm = RuleManager.__new__(RuleManager)
    rm.rules_dir = str(tmp_path)
    rm.test_nginx = lambda: None
    rm.reload_nginx = lambda: None
    with pytest.raises(ValueError):
        rm.write_ml_rule(1000600, GOOD.replace("deny,", "deny,ctl:ruleEngine=Off,"))
    assert list(tmp_path.iterdir()) == []
    assert rm.write_ml_rule(1000600, GOOD) is True
    assert (tmp_path / "ml-1000600.conf").exists()


def test_cve_template_keeps_regex_backslashes_and_escapes_the_message():
    """The CVE auto-patch builds its rule with these two helpers now: the
    operator keeps \\s (doubling it made the rule match a literal "\\s"), and a
    label with quotes cannot close the msg or the action list."""
    from services.rule_manager import escape_secrule_message, escape_secrule_operator
    op = escape_secrule_operator(r"^/api/v\d+/users\s+x")
    assert op == r"^/api/v\d+/users\s+x"
    msg = escape_secrule_message("CVE Auto-Patch: CVE-1 (origin: a'b\"c)")
    rule = (f'SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS "@rx {op}" \\\n'
            f'    "id:1000700,phase:2,deny,status:403,severity:CRITICAL,log,msg:\'{msg}\'"')
    validate_ml_rule_text(rule, 1000700)
    assert re.search(r'^/api/v\d+/users\s+x', "/api/v2/users   x")


def test_cve_scan_uses_the_operator_escaper():
    import inspect
    from api import ml_rules
    src = inspect.getsource(ml_rules)
    assert "escape_secrule_operator(pattern)" in src
    assert "escape_secrule_string(pattern" not in src


@pytest.mark.parametrize("label", ["shop\nSecRuleEngine Off", "a\rb", "x\x00", "   ", "x" * 121])
def test_origin_label_with_control_characters_is_refused(label):
    from pydantic import ValidationError
    from api.origins import OriginCreate, OriginUpdate
    with pytest.raises(ValidationError):
        OriginCreate(label=label, ip="203.0.113.1", port=80)
    with pytest.raises(ValidationError):
        OriginUpdate(label=label)
    assert OriginCreate(label=" My shop (th) ", ip="203.0.113.1", port=80).label == "My shop (th)"


# --------------------------------------------- P4.3 delete scope and one lock

@pytest.mark.parametrize("rule_id", ["managed-10-rules", "tenant-abc-2000000", "ml-1000500",
                                     "custom-1.conf/../x", "../victim", "custom-", "custom-12a"])
def test_rules_api_deletes_only_custom_rules(tmp_path, rule_id):
    rm = RuleManager.__new__(RuleManager)
    rm.rules_dir = str(tmp_path)
    with pytest.raises(ValueError):
        rm.delete_custom_rule(rule_id)


def test_a_delete_that_breaks_nginx_is_rolled_back(tmp_path):
    from services.rule_manager import NginxConfigError
    rm = RuleManager.__new__(RuleManager)
    rm.rules_dir = str(tmp_path)
    (tmp_path / "custom-5.conf").write_text("RULE 5\n")
    rm.test_nginx = lambda: (_ for _ in ()).throw(NginxConfigError("[emerg] id 5 is referenced"))
    rm.reload_nginx = lambda: None
    with pytest.raises(NginxConfigError):
        rm.delete_custom_rule("custom-5")
    assert (tmp_path / "custom-5.conf").read_text() == "RULE 5\n"


def test_every_rule_writer_uses_the_same_lock():
    import services.managed_ruleset as managed
    import services.tenant_rules as tenant
    import services.nginx_site_service as sites
    assert managed._lock is rm_module.RULES_LOCK
    assert tenant._lock is rm_module.RULES_LOCK
    assert sites._reconcile_lock is rm_module.RULES_LOCK


def test_two_concurrent_writes_never_interleave(tmp_path):
    """Two rule changes at once: each one's write, nginx -t and reload happen
    together, never one test seeing the other's half-written state."""
    rm = RuleManager.__new__(RuleManager)
    rm.rules_dir = str(tmp_path)
    events = []

    def slow_test():
        events.append("test-start")
        time.sleep(0.05)
        events.append("test-end")

    rm.test_nginx = slow_test
    rm.reload_nginx = lambda: events.append("reload")
    rules = [dict(id=str(i), variable="ARGS", operator="@rx x", severity="HIGH", message="m") for i in (11, 12)]
    threads = [threading.Thread(target=rm.add_rule, args=(r,)) for r in rules]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert events == ["test-start", "test-end", "reload"] * 2
    assert {p.name for p in tmp_path.iterdir()} == {"custom-11.conf", "custom-12.conf"}


# --------------------------------------------- P4.5 settings and ingest region

@pytest.mark.parametrize("body", [
    {"waf_mode": "blockng"}, {"waf_mode": "off"}, {"paranoia_level": 7}, {"paranoia_level": 0},
    {"inbound_anomaly_threshold": -1}, {"real_ip_header": "X-Evil"}, {"edge_sync_interval_seconds": 0},
    {"telegram_chat_id": "12; rm"}, {"unknown_field": 1},
])
def test_invalid_settings_are_a_422(body):
    from pydantic import ValidationError
    from api.settings import SettingsUpdate
    with pytest.raises(ValidationError):
        SettingsUpdate(**body)


def test_only_an_explicit_detection_only_turns_blocking_off():
    from services.settings_service import render_modsecurity_override
    assert "SecRuleEngine DetectionOnly" in render_modsecurity_override({"waf_mode": "detection_only"})
    for mode in ("blocking", "blockng", None, ""):
        assert "SecRuleEngine On" in render_modsecurity_override({"waf_mode": mode})


@pytest.mark.parametrize("host, claimed, expected", [
    ("10.88.0.2", "th", "th"), ("10.88.0.2", "edge-th", "th"), ("10.88.0.3", "asia", "asia"),
    ("45.154.26.91", "TH", "th"), ("10.88.0.2", "asia", None), ("10.88.0.3", "th", None),
    ("10.88.0.2", "", None), ("203.0.113.5", "th", None),
])
def test_ingest_region_comes_from_the_sending_edge(host, claimed, expected):
    from api.cdn import ingest_region
    assert ingest_region(host, claimed) == expected


def test_ingest_refuses_a_region_that_is_not_the_senders():
    from api import cdn

    class _Req:
        class client:
            host = "10.88.0.2"

    payload = cdn.CdnLogIngestPayload(region="asia", logs=[])
    with pytest.raises(HTTPException) as e:
        asyncio.run(cdn.ingest_cdn_logs(payload, _Req()))
    assert e.value.status_code == 403


# ------------------------------------- re-audit 2026-10-17: validate what is written
def test_comment_line_cannot_hide_actions_from_the_validator():
    text = ('SecRule ARGS "@rx a" "id:1000600,phase:2,deny,\\\n'
            '#,ctl:ruleEngine=Off\\\n'
            '    log"')
    with pytest.raises(ValueError):
        validate_ml_rule_text(text, 1000600)


def test_bare_line_break_inside_a_generated_rule_is_refused():
    text = 'SecRule ARGS "@rx a\nb" "id:1000601,phase:2,deny"'
    with pytest.raises(ValueError):
        validate_ml_rule_text(text, 1000601)


def test_operator_escaper_refuses_line_breaks():
    from services.rule_manager import escape_secrule_operator
    for bad in ("@rx a\nb", "@rx a\rb"):
        with pytest.raises(ValueError):
            escape_secrule_operator(bad)


def test_gen3_template_still_passes():
    from ml.rule_proposal import gen3_rule_text, GEN3_OPERATORS
    det = sorted(GEN3_OPERATORS)[0]
    validate_ml_rule_text(gen3_rule_text(1000602, det), 1000602)
