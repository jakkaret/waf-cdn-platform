"""Proposed SecRules must not let request data break out of the operator string.

The fallback pattern is built from attacker-controlled text. A quote in that text
used to survive re.escape() and close the SecRule operator, so a crafted request
could get a rule proposed that carries its own actions (e.g. ctl:ruleEngine=Off)
and an admin who approves it disables the WAF.
"""
import re

import pytest

from ml.auto_rule_generator import assert_secrule_safe, generate_pending_rule, regex_literal

INJECTION = 'x" "id:1,phase:1,pass,ctl:ruleEngine=Off'


def operator_strings(secrule):
    """The double-quoted strings of a SecRule, honouring backslash escapes."""
    return re.findall(r'"((?:[^"\\]|\\.)*)"', secrule, re.S)  # re.S: the action string uses "\" line continuations


@pytest.mark.parametrize("body", [
    INJECTION,
    'a\\" "id:2,pass',          # backslash before the quote
    "line1\nSecRuleEngine Off",  # newline starting a new directive
    "trailing\\",                # backslash that would escape the closing quote
    "ünïcödé \x00 \t ;|`$(",
])
def test_fallback_rule_has_no_injected_actions(body):
    rule = generate_pending_rule("/form", "POST", body=body)
    secrule = rule["secrule_template"]
    # exactly the operator string and the action string, nothing appended
    operator, actions = operator_strings(secrule)
    assert "\n" not in operator and "\r" not in operator
    assert "ctl:" not in actions and actions.startswith("id:{RULE_ID}")
    assert_secrule_safe(rule["pattern"])


def test_regex_literal_matches_the_same_text():
    for text in [INJECTION, "a.b*c?(d)[e]{f}|g^h$i\\j", "ไทย/ü", "%27%20OR%201=1"]:
        pattern = regex_literal(text)
        assert re.fullmatch(pattern.encode("ascii"), text.encode("utf-8"))
        assert re.fullmatch(r"[A-Za-z0-9_/=&,:\-\\x]*", pattern)  # no "%": ModSecurity macro syntax


def test_query_cut_before_a_percent_escape_stays_loadable():
    # a 40-character cut can end in "%": "...red%" + '"' broke the whole rules file in ModSecurity
    rule = generate_pending_rule("/?p=%3Cstyle%3E%3Atarget%20%7Bcolor%3Ared%7D%3C/style%3E")
    assert "%" not in rule["pattern"]


@pytest.mark.parametrize("pattern", ['@rx a"b', "@rx a\nb", "@rx ab\\", '@rx a\\\\"b'])
def test_assert_secrule_safe_rejects(pattern):
    with pytest.raises(ValueError):
        assert_secrule_safe(pattern)


def test_signature_patterns_still_pass():
    # the fixed templates contain escaped quotes (['\"]) and must stay valid
    for url in ["/login?user=admin' OR '1'='1' --", "/?q=<script>alert(1)</script>", "/../../etc/passwd",
                "/?x=${jndi:ldap://a}", "/?u=http://169.254.169.254/"]:
        assert_secrule_safe(generate_pending_rule(url)["pattern"])
