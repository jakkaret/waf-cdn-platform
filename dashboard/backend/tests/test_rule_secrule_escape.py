"""
Scenario: a WAF rule's operator/message field, once written into a
ModSecurity .conf file, must not let an admin-supplied value break out of
its quoted position in the SecRule directive.

services/rule_manager.py's add_rule() builds the .conf line with:
    safe_operator = str(rule_data['operator']).replace('"', '\\"')
    safe_message  = str(rule_data['message']).replace("'", "\\'")

This only escapes the quote -- the same unsound shape as the ClickHouse bug
fixed for H4 (see tests/test_clickhouse_escape.py and
Docs/15-Progress-Log.md, 2026-08-31): ModSecurity's own config parser
treats backslash as an escape character inside quoted strings, so a
backslash already present in the operator/message consumes the escaping
meant for the character that follows it, letting the admin's own quote
close the field early.

Confirmed against the real engine, not just theorised: writing a rule with
message = "pwned\\' ctl:ruleRemoveById=900001" through the *current*
add_rule() and running `nginx -t` (config test only, never reloaded) on
Main against that file made ModSecurity's rules compiler fail with
"Expecting an action, got: ctl:ruleRemoveById=900001',tag:'end'" -- proof
the msg field closed early and the injected text spilled into the action
list as unparsed tokens. A more carefully shaped payload (one that stays
syntactically valid, e.g. a bare `ctl:ruleRemoveById=<id>` with nothing
trailing) would not error at all -- it would silently add an action,
including one capable of disabling another rule. Rule creation is
admin-gated, so this is a malicious/compromised-admin scenario, not an
unauthenticated one -- still a real trust-boundary gap: an admin should be
constrained to the fields the UI exposes, not able to inject arbitrary
ModSecurity directives through them.

This test reimplements ModSecurity's confirmed backslash-escape parsing
(only \\ and the field's own quote character are special) and asserts that
decoding add_rule()'s output always reconstructs the operator/message
exactly -- the same round-trip property required of the ClickHouse fix.
"""
import re


def _secrule_unescape(s: str) -> str:
    """Reference decoder for ModSecurity's backslash-escape rule inside a
    quoted SecRule field: \\\\ -> \\, \\<quote> -> <quote>, anything else
    passes through unchanged. Mirrors the parser behaviour confirmed live
    against ModSecurity/OWASP CRS on waf-nginx during the fix.
    """
    return re.sub(r"\\(.)", lambda m: m.group(1), s)


ATTACK_STRINGS = [
    "pwned' ctl:ruleRemoveById=900001",       # plain quote (already safe pre-fix)
    "pwned\\' ctl:ruleRemoveById=900001",     # backslash immediately before the quote -- the actual bug
    "a\\\\' trailing",                         # two backslashes then a quote
    "back\\slash and 'quote both present",
    "ordinary message, no special characters",
]


def _quoted_field_after(rule_text: str, marker: str, quote_char: str) -> str:
    """Extract the raw (still-escaped) content between `quote_char`s that
    immediately follows `marker` in rule_text, e.g. marker="msg:" quote_char="'".
    """
    start = rule_text.index(marker) + len(marker)
    assert rule_text[start] == quote_char, (
        f"expected {marker!r} to be immediately followed by {quote_char!r} in {rule_text!r}"
    )
    i = start + 1
    while True:
        if rule_text[i] == "\\":
            i += 2
            continue
        if rule_text[i] == quote_char:
            return rule_text[start + 1:i]
        i += 1


def _create_rule(client, headers, rule_id, operator, message):
    resp = client.post(
        "/api/rules/",
        json={
            "id": rule_id,
            "variable": "ARGS",
            "operator": operator,
            "severity": "CRITICAL",
            "message": message,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def test_message_round_trips_through_written_rule_file(client, register_user, auth_header, tmp_path):
    admin = register_user(email="rule-escape-msg@example.com", username="rule_escape_msg")
    headers = auth_header(admin["access_token"])

    for i, attack in enumerate(ATTACK_STRINGS):
        rule_id = f"90100{i}"
        _create_rule(client, headers, rule_id, "@rx test", attack)

        rule_text = (tmp_path / f"custom-{rule_id}.conf").read_text(encoding="utf-8")
        raw_msg_field = _quoted_field_after(rule_text, "msg:", "'")
        decoded = _secrule_unescape(raw_msg_field)
        assert decoded == attack, (
            f"message {attack!r} did not round-trip through the written rule "
            f"file: got {decoded!r} back (rule_text={rule_text!r}) -- the msg "
            f"field would not close where ModSecurity's own parser expects it to"
        )


def test_operator_round_trips_through_written_rule_file(client, register_user, auth_header, tmp_path):
    admin = register_user(email="rule-escape-op@example.com", username="rule_escape_op")
    headers = auth_header(admin["access_token"])

    for i, attack in enumerate(ATTACK_STRINGS):
        rule_id = f"90200{i}"
        _create_rule(client, headers, rule_id, attack, "benign message")

        rule_text = (tmp_path / f"custom-{rule_id}.conf").read_text(encoding="utf-8")
        raw_operator_field = _quoted_field_after(rule_text, "ARGS ", '"')
        decoded = _secrule_unescape(raw_operator_field)
        assert decoded == attack, (
            f"operator {attack!r} did not round-trip through the written rule "
            f"file: got {decoded!r} back (rule_text={rule_text!r})"
        )


def test_message_round_trips_through_updated_rule_file(client, register_user, auth_header, tmp_path):
    """update_rule() (PUT /api/rules/{id}) duplicates add_rule()'s escaping
    verbatim -- same bug, needs its own proof and its own fix.
    """
    admin = register_user(email="rule-escape-update@example.com", username="rule_escape_update")
    headers = auth_header(admin["access_token"])

    rule_id = "903000"
    _create_rule(client, headers, rule_id, "@rx test", "original message")

    for i, attack in enumerate(ATTACK_STRINGS):
        update_resp = client.put(
            f"/api/rules/custom-{rule_id}",
            json={
                "variable": "ARGS",
                "operator": "@rx test",
                "severity": "CRITICAL",
                "message": attack,
            },
            headers=headers,
        )
        assert update_resp.status_code == 200, update_resp.text

        rule_text = (tmp_path / f"custom-{rule_id}.conf").read_text(encoding="utf-8")
        raw_msg_field = _quoted_field_after(rule_text, "msg:", "'")
        decoded = _secrule_unescape(raw_msg_field)
        assert decoded == attack, (
            f"message {attack!r} did not round-trip through the updated rule "
            f"file: got {decoded!r} back (rule_text={rule_text!r})"
        )
