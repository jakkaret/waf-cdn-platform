"""Gen3-rules: turn the Gen 3 value detectors that fired on a request into general SecRules.

The production rule generator (ml/auto_rule_generator.py, "RF-rules") writes one rule per
flagged request: one of 7 fixed regexes, else a literal of the first 40 characters of the
request. Those literals only ever match the request they came from, and the queue fills with
one near-identical rule per hit.

Gen3-rules propose the detector itself instead: @detectSQLi / @detectXSS (libinjection, the
same detector Gen 3 scores with), or the detector's regex, on ARGS|ARGS_NAMES|REQUEST_FILENAME
with the decoding transforms Gen 3 applies (ml/value_features.normalize_unit). One rule per
detector, so a second request that fires the same detector adds evidence to the pending rule
instead of a new row (dedup_key). Never scoped to a parameter name: the benchmark this was
built on keeps every payload in `p`, so a name-scoped rule would score well there and mean
nothing elsewhere.

Built and measured offline first (ml/security_test/openappsec/propose_rules.py and
backtest_rules.py, BENCHMARK_PLAN_OPENAPPSEC.md section 14); this module is the shared code,
used by the ML API (/generate-rule-gen3, /backtest-rule) and by those scripts.
"""

import re
from urllib.parse import urlsplit

from ml.auto_rule_generator import assert_secrule_safe
from ml.canonical import canonical_request
from ml.feature_engineering import RESTRICTED_FILE_PATTERN
from ml.hybrid_model import request_units
from ml.value_features import DETECTORS, normalize_unit, unit_hits

GENERATOR = "gen3-detector"
GEN3_VARIABLES = "ARGS|ARGS_NAMES|REQUEST_FILENAME"
# Mirrors ml/value_features.normalize_unit: URL decoding (ModSecurity already decoded ARGS once),
# HTML entities, \xHH / \uXXXX escapes, lowercase, null bytes dropped.
GEN3_TRANSFORMS = "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:lowercase,t:removeNulls"
GEN3_OPERATORS = {
    "v_sqli_libinjection": "@detectSQLi",
    "v_xss_libinjection": "@detectXSS",
    **{name: f"@rx {pattern.pattern}" for name, pattern in DETECTORS.items()},
    "v_restricted_file": f"@rx {RESTRICTED_FILE_PATTERN.pattern}",
}

# Shown to the admin who reviews the rule. Severity is the default action weight, not a
# measured risk: the backtest result is what tells the admin whether a rule is safe to deploy.
DETECTOR_INFO = {
    "v_sqli_libinjection": ("SQL Injection", "CRITICAL"),
    "v_xss_libinjection": ("Cross-Site Scripting", "CRITICAL"),
    "v_cmd_injection": ("Command Injection", "CRITICAL"),
    "v_path_traversal": ("Path Traversal", "CRITICAL"),
    "v_sensitive_file": ("Sensitive File Access", "HIGH"),
    "v_template_injection": ("Template Injection", "CRITICAL"),
    "v_nosql_operator": ("NoSQL Injection", "HIGH"),
    "v_ssrf_target": ("SSRF", "HIGH"),
    "v_code_exec": ("Code Execution", "CRITICAL"),
    "v_xml_entity": ("XML External Entity", "HIGH"),
    "v_crlf_header": ("CRLF / Header Injection", "HIGH"),
    "v_restricted_file": ("Restricted File Access", "MEDIUM"),
}

# A backtest replays at most this many logged requests per call.
BACKTEST_MAX_REQUESTS = 5000


def gen3_rule_text(rule_id, detector):
    """The SecRule for one detector. `rule_id` may be the "{RULE_ID}" placeholder the queue stores."""
    operator = GEN3_OPERATORS[detector]
    assert_secrule_safe(operator)
    return (f'SecRule {GEN3_VARIABLES} "{operator}" \\\n'
            f'    "id:{rule_id},phase:2,deny,status:403,log,severity:CRITICAL,\\\n'
            f'    {GEN3_TRANSFORMS},\\\n'
            f"    msg:'ML proposed rule (Gen3-rules): {detector}'\"")


def detectors_fired(method, url, body):
    """Detector names that fired on any unit of the request, as Gen3 computes its value features."""
    parts = urlsplit(url)
    path, query, body = canonical_request(parts.path or "/", parts.query, body)
    texts = [normalize_unit(str(path).lower())[0]]
    texts += [normalize_unit(u)[0] for u in request_units(method, path, query, body)]
    fired = set()
    for text in texts:
        fired.update(name for name, hit in unit_hits(text).items() if hit)
    return fired


def describe_detectors(method, url, body=""):
    """The detectors that fired, labelled for display: [{detector, attack_type, severity}].

    Shown next to the Gen 3 score as the reason behind it. Detectors are value
    features of the model, not its decision: a request can fire one and still
    score below the threshold, or score above it on structure alone.
    """
    return [
        {"detector": name, "attack_type": DETECTOR_INFO[name][0], "severity": DETECTOR_INFO[name][1]}
        for name in sorted(detectors_fired(method, url, body))
        if name in DETECTOR_INFO
    ]


def propose_gen3_rules(method, url, body=""):
    """Pending-rule data (the shape MLRuleService.create_pending_rule stores), one per detector that fired.

    An empty list means the request was flagged, if at all, on structural features alone: there
    is no detector to turn into a rule.
    """
    rules = []
    for detector in sorted(detectors_fired(method, url, body)):
        attack_type, severity = DETECTOR_INFO[detector]
        rules.append({
            "pattern": GEN3_OPERATORS[detector],
            "variable": GEN3_VARIABLES,
            "attack_type": attack_type,
            "severity": severity,
            "secrule_template": gen3_rule_text("{RULE_ID}", detector),
            "source_url": url[:100],
            "source_method": method,
            "generator": GENERATOR,
            "detector": detector,
            "dedup_key": f"{GENERATOR}:{detector}",
        })
    return rules


def _rf_matcher(pattern):
    """Matcher for an RF-rules pattern ("@rx <regex>" on REQUEST_URI|REQUEST_BODY, no transforms).

    ModSecurity runs PCRE on the raw (still URL-encoded) URI; Python's re accepts the same
    syntax for every pattern auto_rule_generator writes (fixed regexes, \\xHH literals).
    """
    if not pattern.startswith("@rx "):
        raise ValueError("only @rx patterns can be backtested")
    try:
        regex = re.compile(pattern[4:])
    except re.error as exc:
        raise ValueError(f"pattern does not compile: {exc}") from exc
    return lambda method, url, body: regex.search(url) is not None or (bool(body) and regex.search(body) is not None)


def backtest_rule(rule, requests):
    """Which of `requests` (dicts with method, url, body) the proposed rule would match.

    `rule` carries `generator` and `detector` (Gen3-rules) or `pattern` (RF-rules). Returns
    {"scanned", "matched", "matched_indexes"}; matched_indexes is capped at 20.
    """
    generator = rule.get("generator") or "rf-regex"
    if generator == GENERATOR:
        detector = rule.get("detector")
        if detector not in GEN3_OPERATORS:
            raise ValueError(f"unknown detector: {detector!r}")
        matches = lambda method, url, body: detector in detectors_fired(method, url, body)  # noqa: E731
    elif generator == "rf-regex":
        matches = _rf_matcher(rule.get("pattern", ""))
    else:
        raise ValueError(f"backtest does not support generator {generator!r}")

    requests = requests[:BACKTEST_MAX_REQUESTS]
    matched = []
    for i, req in enumerate(requests):
        if matches(str(req.get("method") or "GET"), str(req.get("url") or "/"), str(req.get("body") or "")):
            matched.append(i)
    return {"scanned": len(requests), "matched": len(matched), "matched_indexes": matched[:20]}
