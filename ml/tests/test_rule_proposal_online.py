"""Gen3-rules served online (ml/rule_proposal.py, /generate-rule-gen3, /backtest-rule).

The dashboard queue merges repeats on dedup_key, so one detector must always give one key;
every proposed operator must be SecRule-safe; and the backtest must count exactly the
requests a rule would match, or an admin approves a rule that blocks normal traffic.
"""
import pytest

pytest.importorskip("libinjection", reason="libinjection-python not installed")

from ml.auto_rule_generator import assert_secrule_safe, generate_pending_rule  # noqa: E402
from ml.rule_proposal import (  # noqa: E402
    DETECTOR_INFO, GEN3_OPERATORS, GENERATOR, backtest_rule, propose_gen3_rules,
)

SQLI = ("GET", "/?id=1%27%20OR%201=1--", "")
XSS = ("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "")
BENIGN = [("GET", "/static/js/app.2e3a4a11.chunk.js", ""), ("GET", "/products?page=2&sort=price", ""),
          ("POST", "/api/login", '{"user": "alice", "remember": true}')]


def as_requests(rows):
    return [{"method": m, "url": u, "body": b} for m, u, b in rows]


def test_every_detector_has_a_label():
    assert set(DETECTOR_INFO) == set(GEN3_OPERATORS)


def test_sqli_request_proposes_one_detector_rule():
    rules = propose_gen3_rules(*SQLI)
    assert [r["detector"] for r in rules] == ["v_sqli_libinjection"]
    rule = rules[0]
    assert rule["generator"] == GENERATOR
    assert rule["dedup_key"] == "gen3-detector:v_sqli_libinjection"
    assert rule["pattern"] == "@detectSQLi"
    assert rule["attack_type"] == "SQL Injection"
    assert "id:{RULE_ID}" in rule["secrule_template"]
    assert_secrule_safe(rule["pattern"])


def test_same_detector_gives_same_dedup_key_for_different_payloads():
    a = propose_gen3_rules("GET", "/?id=1%27%20OR%201=1--", "")
    b = propose_gen3_rules("POST", "/login", "user=admin%27%20UNION%20SELECT%20password%20FROM%20users--")
    assert a[0]["dedup_key"] == b[0]["dedup_key"]


def test_benign_requests_propose_nothing():
    for row in BENIGN:
        assert propose_gen3_rules(*row) == []


def test_backtest_gen3_counts_only_matching_requests():
    reqs = as_requests(BENIGN + [SQLI] + BENIGN)
    result = backtest_rule({"generator": GENERATOR, "detector": "v_sqli_libinjection"}, reqs)
    assert result == {"scanned": 7, "matched": 1, "matched_indexes": [3]}


def test_backtest_rf_regex_matches_the_raw_uri():
    rule = generate_pending_rule("/q?id=1 union select 1", "GET")
    assert rule["generator"] == "rf-regex" and rule["dedup_key"] == f"rf-regex:{rule['pattern']}"
    reqs = as_requests([("GET", "/q?x=union select", ""), ("GET", "/q?x=hello", "")])
    assert backtest_rule(rule, reqs)["matched_indexes"] == [0]


@pytest.mark.parametrize("rule", [
    {"generator": "cve"},
    {"generator": GENERATOR, "detector": "v_unknown"},
    {"generator": "rf-regex", "pattern": "@rx (unclosed"},
    {"generator": "rf-regex", "pattern": "@detectSQLi"},
])
def test_backtest_refuses_what_it_cannot_evaluate(rule):
    with pytest.raises(ValueError):
        backtest_rule(rule, as_requests(BENIGN))


def test_describe_detectors_labels_what_fired():
    from ml.rule_proposal import describe_detectors

    assert describe_detectors(*XSS) == [
        {"detector": "v_xss_libinjection", "attack_type": "Cross-Site Scripting", "severity": "CRITICAL"}
    ]
    for request in BENIGN:
        assert describe_detectors(*request) == []


def test_api_endpoints():
    from fastapi.testclient import TestClient

    from ml.ml_api import app

    client = TestClient(app)  # no startup event: these endpoints need no model
    res = client.post("/generate-rule-gen3", json={"method": "GET", "url": XSS[1], "body": ""})
    assert res.status_code == 200
    assert res.json()["detectors"] == ["v_xss_libinjection"]

    res = client.post("/backtest-rule", json={
        "rule": {"generator": GENERATOR, "detector": "v_xss_libinjection"},
        "requests": as_requests(BENIGN + [XSS]),
    })
    assert res.status_code == 200 and res.json()["matched"] == 1

    res = client.post("/backtest-rule", json={"rule": {"generator": "cve"}, "requests": []})
    assert res.status_code == 422
