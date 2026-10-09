"""The rule-proposal ablation's building blocks (ml/security_test/openappsec/).

The split must keep one website / one payload on one side, or a rule gets credit on the eval
half for the request it was built from; generated rules must be SecRule-safe; the backtest's
log-only conversion must leave no blocking action behind, or a rule that matched normal traffic
would be hidden by the block and approved.
"""
import re

import pytest

pytest.importorskip("libinjection", reason="libinjection-python not installed")
pytest.importorskip("duckdb", reason="duckdb not installed (benchmark tooling only)")

from ml.auto_rule_generator import assert_secrule_safe, generate_pending_rule  # noqa: E402
from ml.security_test.openappsec.backtest_rules import log_only  # noqa: E402
from ml.security_test.openappsec.propose_rules import GEN3_OPERATORS, detectors_fired, gen3_rule_text  # noqa: E402
from ml.security_test.openappsec.split import EVAL, GEN, group_of, half_of  # noqa: E402


def test_same_payload_as_get_and_post_lands_on_one_side():
    payload = "%3Cscript%3Ealert(1)%3C/script%3E"
    get = group_of("Malicious", "xss", f"/?p={payload}", "")
    post = group_of("Malicious", "xss", "/", f"p={payload}")
    double = group_of("Malicious", "xss", "/", "p=%253Cscript%253Ealert(1)%253C/script%253E")
    assert get == post == double


def test_payloads_differing_after_a_nul_byte_stay_separate_groups():
    import pandas as pd

    from ml.security_test.openappsec.split import add_halves

    df = pd.DataFrame({"DataSetType": ["Malicious"] * 2, "TestName": ["traversal"] * 2, "url": ["/", "/"],
                       "data": ["p=../../etc/passwd", "p=../../etc/passwd%00index.html"]})
    out = add_halves(df)  # asserts no group on both halves
    assert out.group.nunique() == 2


def test_legitimate_split_is_by_site_and_deterministic():
    a = half_of("Legitimate", "browsing_2024_agoda", "/a.js", "")
    assert a == half_of("Legitimate", "browsing_2024_agoda", "/other?x=1", "big body")
    halves = {half_of("Legitimate", f"site{i}", "/", "") for i in range(50)}
    assert halves == {GEN, EVAL}


def test_gen3_rules_are_secrule_safe_and_never_parameter_scoped():
    for n, detector in enumerate(GEN3_OPERATORS):
        text = gen3_rule_text(1100000 + n, detector)
        assert text.startswith("SecRule ARGS|ARGS_NAMES|REQUEST_FILENAME ")
        assert "ARGS:" not in text  # every malicious request of the dataset is in `p`
        assert_secrule_safe(GEN3_OPERATORS[detector])


@pytest.mark.parametrize("method,url,body,expected", [
    ("GET", "/?p=%3Cscript%3Ealert(1)%3C/script%3E", "", "v_xss_libinjection"),
    ("POST", "/", "p=../../../etc/passwd", "v_path_traversal"),
    ("GET", "/?id=1%27%20OR%201=1--", "", "v_sqli_libinjection"),
    ("GET", "/?p=%24%7Bjndi%3Aldap%3A//x/a%7D", "", "v_template_injection"),
])
def test_detectors_fired(method, url, body, expected):
    assert expected in detectors_fired(method, url, body)


def test_benign_request_fires_nothing():
    assert detectors_fired("GET", "/static/js/app.2e3a4a11.chunk.js", "") == set()


@pytest.mark.parametrize("rule", [
    generate_pending_rule("/login?user=admin' OR '1'='1' --")["secrule_template"].replace("{RULE_ID}", "1000500"),
    gen3_rule_text(1100000, "v_path_traversal"),
])
def test_log_only_removes_blocking(rule):
    text = log_only(rule)
    assert "deny" not in text and not re.search(r"status:\d+", text)
    assert "pass,auditlog," in text
    assert re.search(r"id:\d+", text)
