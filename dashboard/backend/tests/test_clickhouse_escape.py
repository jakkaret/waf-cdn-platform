"""
Scenario: H4 -- a backslash immediately before a quote no longer lets a
LIKE-pattern value break out of its ClickHouse string literal.

Locks in the fix in services/clickhouse_service.py's escape_like_value():
the previous code at 6 call sites (get_logs' domain/search/method filters,
analytics.py's _build_domain_pattern_sql, cdn.py's per-domain LIKE builder,
logs.py's explain-by-id lookup) only escaped the quote
(value.replace("'", "\\'")), which is unsound against ClickHouse's own
backslash-escape rule: a backslash already present in the input consumes
the escaping meant for the *next* character, so an attacker's own quote
survives to close the string early. Reproduced and confirmed against a live
ClickHouse instance during the fix (see Docs/15-Progress-Log.md,
2026-08-31): the pre-fix escaping of "x\\' OR 1=1 -- " breaks a surrounding
SQL expression with a syntax error; the fixed escaping round-trips it as an
inert 14-character string.

This test reimplements ClickHouse's own backslash-escape parsing (only \\
and \' are special inside a single-quoted string -- the same rule the
production code already relied on for the plain-quote case) and asserts
that decoding escape_like_value()'s output always reconstructs the exact
original input. That is the property a LIKE-pattern escaper must have:
whatever the caller wrapped it in ('%...%'), the payload between the
quotes must decode back to the caller's literal value and never anything
else.
"""
import re

from services.clickhouse_service import escape_like_value


def _clickhouse_unescape(s: str) -> str:
    """Reference decoder for ClickHouse's backslash-escape rule inside a
    single-quoted string literal: \\\\ -> \\, \\' -> ', anything else
    passes through unchanged. Mirrors the parser behaviour verified live
    against ClickHouse 26.7.3 during the fix.
    """
    return re.sub(r"\\(.)", lambda m: m.group(1), s)


ATTACK_STRINGS = [
    "x' OR 1=1 -- ",                       # plain quote (already safe pre-fix)
    "x\\' OR 1=1 -- ",                     # backslash immediately before the quote -- the actual bug
    "a\\\\' OR 1=1 -- ",                    # two backslashes then a quote
    "'; DROP TABLE access_logs; --",
    "back\\slash and 'quote both present",
    "",
    "no special characters at all",
    "trailing backslash\\",
]


def test_escape_like_value_round_trips_every_attack_string():
    for original in ATTACK_STRINGS:
        escaped = escape_like_value(original)
        # The escaper must never emit a bare, unescaped quote: every quote
        # in its output has to be reachable only via the \' escape, i.e.
        # decoding must reproduce the exact original -- not a prefix of it
        # (which is what happens when a quote closes the string early).
        decoded = _clickhouse_unescape(escaped)
        assert decoded == original, (
            f"escape_like_value({original!r}) = {escaped!r}, which decodes "
            f"back to {decoded!r} instead of the original -- the string "
            f"literal would not round-trip safely in ClickHouse"
        )


def test_escape_like_value_wrapped_in_quotes_has_no_premature_terminator():
    """Simulates exactly how every call site uses this function: wrapped in
    '%...%' as a LIKE pattern. No unescaped quote may appear before the
    closing quote the call site adds.
    """
    for original in ATTACK_STRINGS:
        escaped = escape_like_value(original)
        literal = f"'%{escaped}%'"
        # Walk the literal accounting for backslash-escapes; the only
        # unescaped quote allowed is the final closing one.
        i = 1  # skip the opening quote
        n = len(literal)
        while i < n - 1:
            if literal[i] == "\\":
                i += 2
                continue
            assert literal[i] != "'", (
                f"unescaped quote found before the closing quote in {literal!r} "
                f"(original input: {original!r}) -- this breaks out of the "
                f"string literal"
            )
            i += 1


def test_escape_like_value_leaves_ordinary_input_unchanged():
    assert escape_like_value("juice.waf-it-kku.online") == "juice.waf-it-kku.online"
    assert escape_like_value("192.168.1.1") == "192.168.1.1"
