"""
Gen 3 value-level (per-unit) detector features.

The 36 request-level features in ml/feature_engineering.py are computed over
the whole request, so the model can (and did) learn dataset context instead of
attack evidence: the top LightGBM importances of candidate 20260927-205652
are query_body_entropy, url_path_entropy, avg/max_param_length and path_depth,
which mostly say *which dataset* a request came from, and leave-one-source-out
attack recall collapses to 6-13%. Request-wide ratios are also diluted when a
short payload sits in a long benign request.

These features are computed per unit instead (path segment, parameter name or
value, JSON leaf: ml.hybrid_model.request_units) after extra normalisation,
then pooled with max/count over the units. A payload scores the same whether
it arrives as `/?p=<payload>` or inside a real application's `/api/run`
request, so every feature here is a candidate for a +1 monotone constraint.

SQLi/XSS use libinjection (the detector behind OWASP CRS 942100/941100,
pip package `libinjection-python`); the rest are narrow grammar checks.
"""

import html
import re
from urllib.parse import unquote

from ml.feature_engineering import ATTACK_KEYWORD_PATTERN, RESTRICTED_FILE_PATTERN, SPECIAL_CHARS
from ml.hybrid_model import request_units

try:
    import libinjection
except ImportError as exc:  # fail loudly: silently zeroed features would change the model contract
    raise ImportError("ml/value_features.py needs libinjection: pip install libinjection-python") from exc

MAX_DECODE_ROUNDS = 3

_HEX_ESCAPE = re.compile(r"\\x([0-9a-f]{2})", re.I)
_UNICODE_ESCAPE = re.compile(r"(?:\\u|%u)([0-9a-f]{4})", re.I)
_SQL_INLINE_COMMENT = re.compile(r"/\*.*?\*/")
_WHITESPACE = re.compile(r"\s+")

# Shell: a command separator followed by a well-known binary and a command-like
# argument (flag, path, number, URL, metacharacter or nothing), or shell-only
# syntax. Ambiguous English words (more, less, head, net, find) are left out and
# prose such as "; cat is friendly" does not match.
_SHELL_BINARIES = (
    r"cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|ksh|python\d?|perl|php|ruby|"
    r"ping|nslookup|dig|sleep|echo|rm|chmod|chown|tail|env|ifconfig|ipconfig|powershell|cmd|certutil|"
    r"tftp|telnet|base64|xargs|sudo|busybox|awk|sed|tee|touch|mkfifo|systeminfo|net\.exe|type|dir|netstat"
)
# Unambiguous admin commands that may open a value with no separator before them
_STANDALONE_BINARIES = r"whoami|ipconfig|ifconfig|netstat|uname|systeminfo|powershell|certutil|busybox"
_CMD_SEPARATOR = r"(?:[;|`\n&]|\$\()"
_CMD_ARGUMENT = r"(?=\s*$|[;|&<>`$)'\"]|\s+(?:[-/.~$\d'\"\\]|[a-z]:\\|[a-z]+://))"
# Command substitution ($(...) and backticks) must also name a binary: bot-detection
# sensor strings in real browsing traffic are random text full of "$(" and "`".
CMD_INJECTION_PATTERN = re.compile(
    _CMD_SEPARATOR + r"\s*(?:/(?:usr/)?s?bin/)?(?:" + _SHELL_BINARIES + r")" + _CMD_ARGUMENT
    + r"|" + _CMD_SEPARATOR + r"\s*(?:echo|printf?)\s+\S"                     # echo probes: ;echo MARKER
    + r"|\$\(\s*(?:" + _SHELL_BINARIES + r")\b|\$\(\(\s*\d"                   # $(cmd ...), $((1+2))
    + r"|`\s*(?:" + _SHELL_BINARIES + r")\b[^`]*`"                            # `cmd ...`
    + r"|^(?:" + _STANDALONE_BINARIES + r")(?=\s|$)"
    + r"|\$\{ifs\}|/bin/(?:ba)?sh\b|\bcmd(?:\.exe)?\s*/c\b"
)
TRAVERSAL_PATTERN = re.compile(r"\.\.(?:[/\\]|%[0-9a-z]{2})")
# Path detectors run on a copy with evasion junk undone: control bytes (null-byte
# padding) removed, overlong UTF-8 separators (%c0%af, %f0%80%80%af -> U+FFFD runs)
# read as "/", and unicode slashes / literal 0x2e, 0x2f, 0x5c mapped back.
_PATH_JUNK = re.compile(r"[\x00-\x1f\x7f]")
_PATH_OVERLONG = re.compile(r"�+")
_PATH_HEX = {"0x2e": ".", "0x2f": "/", "0x5c": "\\", "∕": "/", "∖": "\\", "⁄": "/"}
_PATH_HEX_PATTERN = re.compile("|".join(map(re.escape, _PATH_HEX)))
SENSITIVE_FILE_PATTERN = re.compile(
    r"/etc/(?:passwd|shadow|group|hosts|issue)|/proc/self/|c:[/\\]windows|win\.ini|boot\.ini|/var/log/"
)
# Expressions only: plain placeholders such as ad-tech macros (${gdpr}, ${bsw_uuid})
# and mustache/angular variables ({{name}}) are unexpanded benign templates.
_PLACEHOLDER = r"\s*[a-z_][a-z0-9_.-]*\s*"
TEMPLATE_PATTERN = re.compile(
    r"\{\{(?!" + _PLACEHOLDER + r"\}\}).*?\}\}|\$\{(?!" + _PLACEHOLDER + r"\})[^}]*\}"
    r"|#\{(?!" + _PLACEHOLDER + r"\})[^}]*\}|<%=?.*?%>|\$\{jndi:"
)
NOSQL_PATTERN = re.compile(r"^\$(?:ne|gt|gte|lt|lte|regex|where|or|and|in|nin|exists|expr|not)$|\[\$(?:ne|gt|gte|lt|lte|regex|where|in|nin|exists)\]")
SSRF_PATTERN = re.compile(
    r"(?:gopher|dict|file|ldap|tftp|jar|netdoc)://"
    r"|(?:https?|ftp)://(?:[^/@]*@)?(?:127\.|0\.0\.0\.0|localhost|\[::1?\]|169\.254\.|10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|metadata\.google\.internal|0x7f|2130706433)"
)
# Not after "@", "." or "$": GraphQL directives (@include(if: ...)) and method calls are benign.
CODE_EXEC_PATTERN = re.compile(
    r"(?<![@.$\w])(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|assert|base64_decode|phpinfo|"
    r"file_get_contents|file_put_contents|fopen|include|require(?:_once)?|include_once|runtime\.getruntime|"
    r"processbuilder|__import__|os\.system|subprocess)\s*\("
    r"|(?:php|data|expect|zip|phar)://|<\?php|<\?=|\.getclass\(\)|java\.lang\."
)
XML_ENTITY_PATTERN = re.compile(r"<!doctype[^>]*\[|<!entity|\bsystem\s+[\"'](?:file|https?|php|expect):")
# A line break followed by a header an attacker would inject. Any "newline + word:"
# also matched multi-line GraphQL queries and multipart bodies in real browsing.
CRLF_HEADER_PATTERN = re.compile(
    r"[\r\n]\s*(?:set-cookie|location|refresh|content-length|content-type|x-xss-protection|"
    r"access-control-allow-[a-z-]+|http/1\.[01])\s*[:\s]"
)
MULTIPART_PATTERN = re.compile(r"content-disposition:\s*form-data|filename=\"")  # parse_qsl splits parts at "="

DETECTORS = {
    "v_cmd_injection": CMD_INJECTION_PATTERN,
    "v_path_traversal": TRAVERSAL_PATTERN,
    "v_sensitive_file": SENSITIVE_FILE_PATTERN,
    "v_template_injection": TEMPLATE_PATTERN,
    "v_nosql_operator": NOSQL_PATTERN,
    "v_ssrf_target": SSRF_PATTERN,
    "v_code_exec": CODE_EXEC_PATTERN,
    "v_xml_entity": XML_ENTITY_PATTERN,
    "v_crlf_header": CRLF_HEADER_PATTERN,
}

# Counts of units a detector fired on (libinjection first, then DETECTORS order)
DETECTOR_COLUMNS = ["v_sqli_libinjection", "v_xss_libinjection", *DETECTORS, "v_restricted_file"]
VALUE_FEATURE_COLUMNS = DETECTOR_COLUMNS + [
    "v_detector_units",       # units with at least one detector hit
    "v_max_keyword_hits",     # ATTACK_KEYWORD_PATTERN hits in the single worst unit
    "v_max_special_count",    # SPECIAL_CHARS in the single worst unit
    "v_max_special_ratio",    # same, as a fraction of that unit (units shorter than 3 chars skipped)
    "v_max_decode_layers",    # extra decode rounds a unit still needed after request_units()
]

# Every value feature only ever adds evidence of an attack.
VALUE_MONOTONE_COLUMNS = list(VALUE_FEATURE_COLUMNS)


def normalize_unit(unit):
    """Undo the evasions libinjection and the regexes would otherwise miss.

    Returns (normalised text, decode rounds that still changed the unit).
    """
    text, layers = unit, 0
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(text)
        decoded = html.unescape(decoded)
        decoded = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
        decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
        if decoded == text:
            break
        text, layers = decoded, layers + 1
    text = _SQL_INLINE_COMMENT.sub(" ", text.lower())
    # %uD800 / \uDAA3 decode to lone surrogates, which libinjection cannot encode
    # (UnicodeEncodeError): a request crafted with one would crash scoring.
    text = text.encode("utf-8", "replace").decode("utf-8")
    return text, layers


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0e-\x1f\x7f�]")
BINARY_CONTROL_RATIO = 0.05


def is_binary(text):
    """Protobuf/compressed/beacon bodies: libinjection and the regexes fire on their random bytes."""
    # A few control characters (null-byte evasion such as "..%00/etc/passwd") do not make a unit binary
    n = len(_CONTROL_CHARS.findall(text))
    return n >= 4 and n / len(text) > BINARY_CONTROL_RATIO


PATH_DETECTORS = ("v_path_traversal", "v_sensitive_file")


def unit_hits(text):
    """Detector name -> bool for one normalised unit.

    Path detectors always run, on a copy with evasion junk removed; the others
    are skipped for binary units, where they only ever fired on random bytes.
    """
    path_text = _PATH_OVERLONG.sub("/", _PATH_JUNK.sub("", text))
    path_text = _PATH_HEX_PATTERN.sub(lambda m: _PATH_HEX[m.group()], path_text)
    hits = dict.fromkeys(DETECTOR_COLUMNS, False)
    hits["v_path_traversal"] = TRAVERSAL_PATTERN.search(path_text) is not None
    hits["v_sensitive_file"] = SENSITIVE_FILE_PATTERN.search(path_text) is not None
    hits["v_restricted_file"] = RESTRICTED_FILE_PATTERN.search("/" + path_text) is not None
    if is_binary(text):
        return hits
    hits["v_sqli_libinjection"] = bool(libinjection.is_sql_injection(text)["is_sqli"])
    hits["v_xss_libinjection"] = bool(libinjection.is_xss(text)["is_xss"])
    for name, pattern in DETECTORS.items():
        if name not in PATH_DETECTORS:
            hits[name] = pattern.search(text) is not None
    if hits["v_crlf_header"] and MULTIPART_PATTERN.search(text):
        hits["v_crlf_header"] = False
    return hits


def extract_value_features_from_units(units, path=""):
    """Pool per-unit detector hits and signal strengths over a request's units.

    request_units() splits the path on "/", which hides traversal
    (`/a/../../etc/passwd` -> "..", "..", "etc", "passwd"), so the whole path is
    checked by the detectors as one more unit. It adds no learned context: the
    detectors are fixed patterns, and the per-unit maxima skip it.
    """
    feats = dict.fromkeys(VALUE_FEATURE_COLUMNS, 0)
    feats["v_max_special_ratio"] = 0.0
    if path:
        text, _ = normalize_unit(str(path).lower())
        for name, hit in unit_hits(text).items():
            feats[name] += hit
    for unit in units:
        text, layers = normalize_unit(unit)
        hits = unit_hits(text)
        for name, hit in hits.items():
            feats[name] += hit
        feats["v_detector_units"] += any(hits.values())
        feats["v_max_keyword_hits"] = max(feats["v_max_keyword_hits"], len(ATTACK_KEYWORD_PATTERN.findall(text)))
        special = sum(1 for c in text if c in SPECIAL_CHARS)
        feats["v_max_special_count"] = max(feats["v_max_special_count"], special)
        if len(text) >= 3:
            feats["v_max_special_ratio"] = max(feats["v_max_special_ratio"], round(special / len(text), 4))
        feats["v_max_decode_layers"] = max(feats["v_max_decode_layers"], layers)
    return feats


def extract_value_features(method, uri, query, body):
    """Value features for one request given its parts (the trainer's row layout)."""
    return extract_value_features_from_units(request_units(method, uri, query, body), uri)
