import math
import re
import urllib.parse
from typing import Dict, Union, List, Any

# Special characters specifically indicative of injections (SQLi, XSS, Path Traversal, Command Injection)
# Note: '=', '&', '?', '/', '-', '_', '+', '.', '@', '!' are excluded because they are standard in passwords, emails, and URLs.
SPECIAL_CHARS = set("'\"`;<>\\$()|`^~*#{}[]")

# Comprehensive Attack Keywords Pattern (covering SQLi, XSS, Path Traversal, RCE, SSRF, SSTI, NoSQL, Log4j)
ATTACK_KEYWORD_PATTERN = re.compile(
    r"(?i)("
    # SQL Injection
    r"select\s+|union\s+(?:all\s+)?select|insert\s+into|update\s+\w+\s+set|delete\s+from|"
    r"drop\s+(?:table|database)|exec\s*\(|where\s+|from\s+|or\s+['\"]?1['\"]?\s*=\s*['\"]?1|"
    r"and\s+['\"]?1['\"]?\s*=\s*['\"]?1|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|"
    r"into\s+(?:out|dump)file|load_file\s*\(|concat\s*\(|pg_sleep|"
    # XSS
    r"<script|javascript:|alert\s*\(|eval\s*\(|onerror\s*=|onload\s*=|document\.cookie|"
    r"<svg|<iframe|<img\s+[^>]*onerror|<body\s+onload|fetch\s*\(|"
    # Path Traversal & LFI
    r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|"
    # Command Injection / RCE
    r"(?:\||;|`|&&|\$\()\s*(?:cat|nc|wget|curl|bash|sh|whoami|id|uname|python|perl|powershell)\b|"
    r"/bin/sh|/bin/bash|\$\{IFS\}|"
    # SSRF
    r"169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|"
    # SSTI
    r"\{\{.*?\}\}|\$\{.*?\}|\#\{.*?\}|"
    # NoSQL Injection
    r"\$gt|\$ne|\$where|\$regex|\$or|\$eq|"
    # Log4j / JNDI
    r"\$\{jndi:(?:ldap|rmi|dns):"
    r")"
)

HTML_TAG_PATTERN = re.compile(r"<[a-zA-Z/][^>]*>", re.IGNORECASE)
SQL_OP_PATTERN = re.compile(r"(?i)\b(union\s+select|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|select\s+.*?\s+from|drop\s+table|exec\s*\()\b")
SSRF_PATTERN = re.compile(r"(?i)(169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.google|internal\.corp)")
SSTI_NOSQL_PATTERN = re.compile(r"(\{\{.*?\}\}|\$\{.*?\}|\#\{.*?\}|\$ne|\$gt|\$where|\$regex|\$\{jndi:)")

# Gen 3 mutation and structure signals. These complement the existing
# signature features and are computed from the decoded request so encoded
# evasions remain visible to the model.
STRUCTURAL_DELIMITER_PATTERN = re.compile(r"[()\[\]{}<>]")
COMMENT_EVASION_PATTERN = re.compile(r"(?i)(?:/\*|\*/|--(?:\s|$)|(?<![\w-])#(?:\s|$))")
INLINE_FUNCTION_PATTERN = re.compile(
    r"(?i)\b(?:char|nchar|ascii|substring|substr|sleep|benchmark|load_file|"
    r"concat|eval|exec|system|preg_replace)\s*\("
)
JSON_INJECTION_PATTERN = re.compile(
    r"(?i)(?:[\"\']?\$(?:gt|ne|where|regex|or|eq|in|nin)[\"\']?\s*:|"
    r"\$(?:gt|ne|where|regex|or|eq|in|nin)\b)"
)
# ASCII URL-encoded bytes (%00 - %7F). Multi-byte UTF-8 international characters
# (%80 - %FF like Thai, Chinese, accents) are legitimate text and excluded from obfuscation penalty.
ENCODED_BYTE_PATTERN = re.compile(r"%[0-7][0-9a-fA-F]")
ENCODED_ATTACK_TOKEN_PATTERN = re.compile(r"(?i)%(?:25[0-9a-fA-F]{2}|27|22|3c|3e|2f|5c|60|24|7b|7d|3b|28|29|5b|5d)")
SUSPICIOUS_PATH_MARKER_PATTERN = re.compile(r"(?i)(?:\.bak|\.old|\.inc|\.sql|~)(?:$|[/?#])")
# Restricted/sensitive file probes, following OWASP CRS 930130 (restricted-files):
# secrets, VCS metadata and server config that no public page ever serves.
# In the VPS ModSecurity data, 679 of 923 payload-rule attacks are these probes
# (/.env, /.git/config, /.aws/credentials) and none tripped any other feature.
RESTRICTED_FILE_PATTERN = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.env(?:[._-][\w.-]*)?|\.git|\.svn|\.hg|\.bzr|\.aws|\.ssh|\.docker|\.kube|\.gnupg"
    r"|\.htaccess|\.htpasswd|\.npmrc|\.pypirc|\.netrc|\.bash_history|\.DS_Store"
    r"|id_rsa|id_dsa|id_ecdsa|id_ed25519|wp-config\.php|web\.config"
    r")(?=$|[/?#.])"
)
CONTROL_CHAR_ENCODED_PATTERN = re.compile(r"(?i)%(?:0[0-9a-f]|1[0-9a-f]|7f)")

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features_from_request(
    url: str = "",
    method: str = "GET",
    body: str = "",
    headers: str = ""
) -> Dict[str, Union[int, float]]:
    """
    Extract numerical features from an HTTP Request for WAF Machine Learning.
    Automatically decodes URL-encoding and nested entities for maximum accuracy.
    """
    raw_url = str(url or "")
    raw_body = str(body or "")
    
    # 0. URL Decode for maximum visibility into obfuscated payloads
    decoded_url = urllib.parse.unquote_plus(urllib.parse.unquote_plus(raw_url))
    decoded_body = urllib.parse.unquote_plus(urllib.parse.unquote_plus(raw_body))
    
    # Payload content without HTTP method
    payload_str = f"{decoded_url} {decoded_body}".strip()
    payload_len = max(len(payload_str), 1)
    
    combined_str = f"{method} {decoded_url} {decoded_body}".strip()
    total_len = max(len(combined_str), 1)

    # 1. Separate URL path and query/body components
    parsed_url = urllib.parse.urlsplit(decoded_url)
    path_component = parsed_url.path or decoded_url.split("?", 1)[0]
    query_body_component = f"{parsed_url.query} {decoded_body}".strip()

    # Static asset detection: common web file extensions that are always benign
    STATIC_EXT = {".html", ".htm", ".css", ".js", ".png", ".jpg", ".jpeg",
                  ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                  ".map", ".webp", ".avif", ".mp4", ".webm", ".pdf"}
    url_path_lower = path_component.lower()
    is_static_asset = 1 if any(url_path_lower.endswith(ext) for ext in STATIC_EXT) else 0

    raw_path_entropy = calculate_shannon_entropy(path_component)
    # Normalize entropy by path length to prevent short URLs from having
    # disproportionately high entropy that confuses them with attack probes.
    # Static assets (.css, .js, .png, etc.) have benign file paths and are zeroed.
    path_len = max(len(path_component), 1)
    if is_static_asset:
        url_path_entropy = 0.0
    else:
        url_path_entropy = raw_path_entropy * min(path_len / 15.0, 1.0) if path_len < 15 else raw_path_entropy
    suspicious_path_marker_count = (
        len(SUSPICIOUS_PATH_MARKER_PATTERN.findall(path_component))
        + len(RESTRICTED_FILE_PATTERN.findall(path_component))
    )
    query_body_entropy = calculate_shannon_entropy(query_body_component)

    # 2. Special Characters Count & Ratio (calculated on payload)
    special_char_count = sum(1 for char in payload_str if char in SPECIAL_CHARS)
    special_char_ratio = special_char_count / payload_len

    # 3. Parameter count (only flag if extreme parameter pollution)
    raw_param_count = decoded_url.count('&') + (1 if '=' in decoded_url else 0)
    has_excessive_params = 1 if raw_param_count > 10 else 0

    # 4. Method
    method_is_post = 1 if method.upper() == "POST" else 0

    # 5. Attack keyword occurrences & HTML tags & Path Traversal
    keyword_matches = len(ATTACK_KEYWORD_PATTERN.findall(combined_str))
    html_tag_matches = len(HTML_TAG_PATTERN.findall(combined_str))
    path_traversal_depth = combined_str.count('../') + combined_str.count('..\\') + combined_str.count('..%2f')
    
    quote_single_diff = abs(combined_str.count("'") % 2)
    quote_double_diff = abs(combined_str.count('"') % 2)
    quote_unbalanced = 1 if (quote_single_diff + quote_double_diff) > 0 else 0

    # 6. Specific domain indicator features
    has_sql_operator = 1 if SQL_OP_PATTERN.search(combined_str) else 0
    has_ssrf_token = 1 if SSRF_PATTERN.search(combined_str) else 0
    has_ssti_nosql = 1 if SSTI_NOSQL_PATTERN.search(combined_str) else 0
    is_oversized_payload = 1 if total_len > 2048 else 0

    # 7. Gen 3 mutation and structural anomaly features.
    encoded_source = f"{raw_url} {raw_body}"
    encoded_char_count = len(ENCODED_BYTE_PATTERN.findall(encoded_source))
    double_encoded_count = len(re.findall(r"%25[0-9a-fA-F]{2}", encoded_source))
    encoded_attack_token_count = len(ENCODED_ATTACK_TOKEN_PATTERN.findall(encoded_source))
    encoded_char_ratio = encoded_char_count / max(len(encoded_source), 1)
    delimiter_count = len(STRUCTURAL_DELIMITER_PATTERN.findall(payload_str))
    delimiter_ratio = delimiter_count / payload_len
    comment_token_count = len(COMMENT_EVASION_PATTERN.findall(combined_str))
    inline_function_count = len(INLINE_FUNCTION_PATTERN.findall(combined_str))
    json_operator_count = len(JSON_INJECTION_PATTERN.findall(combined_str))

    # 8. Structural parameter & verb signals
    method_upper = str(method or "GET").strip().upper()
    method_is_uncommon = 1 if method_upper not in {"GET", "POST", "HEAD"} else 0
    path_depth = raw_url.split("?")[0].count("/")

    query_part = raw_url.split("?", 1)[1] if "?" in raw_url else ""
    combined_params = f"{query_part}&{raw_body}".strip("&")
    param_keys = []
    param_val_lens = []
    if combined_params:
        for item in combined_params.split("&"):
            if not item:
                continue
            parts = item.split("=", 1)
            param_keys.append(parts[0])
            if len(parts) > 1:
                param_val_lens.append(len(parts[1]))
            else:
                param_val_lens.append(0)

    param_count = len(param_keys)
    max_param_length = max(param_val_lens) if param_val_lens else 0
    has_duplicate_param_keys = 1 if len(param_keys) > len(set(param_keys)) else 0

    # Parameter tampering & value punctuation signals
    param_key_has_capital = 1 if any(any(c.isupper() for c in k) for k in param_keys) else 0
    # Punctuation indicative of parameter tampering/injection. Note: '+' is standard space encoding in URLs and excluded.
    punct_chars = set(",?|;:\\")
    param_value_punctuation_count = sum(sum(1 for c in str(v) if c in punct_chars) for v in param_val_lens) if False else 0
    # Precise punctuation count in decoded values:
    query_and_body = f"{query_part} {raw_body}"
    param_value_punctuation_count = sum(1 for c in query_and_body if c in punct_chars)

    has_control_char_encoding = len(CONTROL_CHAR_ENCODED_PATTERN.findall(encoded_source))
    non_printable_char_count = sum(1 for c in payload_str if ord(c) < 32 and c not in "\r\n\t")

    # 8b. Parameter tampering composite signals
    # avg_param_length: low average value length with many params suggests form-fuzzing
    avg_param_length = round(sum(param_val_lens) / max(len(param_val_lens), 1), 2)
    # param_anomaly_score: composite score combining multiple weak tampering signals
    #   - high param count (> 5), capital keys, excessive punctuation, but no attack keywords
    _tampering_signals = (
        (1 if param_count > 5 else 0) +
        param_key_has_capital +
        (1 if param_value_punctuation_count > 2 else 0) +
        has_excessive_params +
        has_duplicate_param_keys
    )
    param_anomaly_score = _tampering_signals if keyword_matches == 0 and special_char_count == 0 else 0

    # 9. Clean Benign Indicator
    is_clean_structure = 1 if (
        special_char_count == 0 and
        keyword_matches == 0 and
        html_tag_matches == 0 and
        path_traversal_depth == 0 and
        quote_unbalanced == 0 and
        has_sql_operator == 0 and
        has_ssrf_token == 0 and
        has_ssti_nosql == 0 and
        has_excessive_params == 0 and
        is_oversized_payload == 0 and
        method_is_uncommon == 0 and
        has_control_char_encoding == 0 and
        non_printable_char_count == 0 and
        param_key_has_capital == 0 and
        param_value_punctuation_count == 0
    ) else 0

    return {
        "special_char_count": special_char_count,
        "special_char_ratio": round(special_char_ratio, 4),
        "url_path_entropy": round(url_path_entropy, 4),
        "suspicious_path_marker_count": suspicious_path_marker_count,
        "query_body_entropy": round(query_body_entropy, 4),
        "encoded_char_ratio": round(encoded_char_ratio, 4),
        "double_encoded_count": double_encoded_count,
        "encoded_attack_token_count": encoded_attack_token_count,
        "delimiter_count": delimiter_count,
        "delimiter_ratio": round(delimiter_ratio, 4),
        "comment_token_count": comment_token_count,
        "inline_function_count": inline_function_count,
        "json_operator_count": json_operator_count,
        "keyword_matches": keyword_matches,
        "html_tag_matches": html_tag_matches,
        "path_traversal_depth": path_traversal_depth,
        "quote_unbalanced": quote_unbalanced,
        "has_sql_operator": has_sql_operator,
        "has_ssrf_token": has_ssrf_token,
        "has_ssti_nosql": has_ssti_nosql,
        "is_oversized_payload": is_oversized_payload,
        "is_clean_structure": is_clean_structure,
        "has_excessive_params": has_excessive_params,
        "method_is_post": method_is_post,
        "is_static_asset": is_static_asset,
        "method_is_uncommon": method_is_uncommon,
        "path_depth": path_depth,
        "max_param_length": max_param_length,
        "param_count": param_count,
        "has_duplicate_param_keys": has_duplicate_param_keys,
        "has_control_char_encoding": has_control_char_encoding,
        "non_printable_char_count": non_printable_char_count,
        "param_key_has_capital": param_key_has_capital,
        "param_value_punctuation_count": param_value_punctuation_count,
        "avg_param_length": avg_param_length,
        "param_anomaly_score": param_anomaly_score,
    }

BASE_FEATURE_COLUMNS = [
    "special_char_count",
    "special_char_ratio",
    "keyword_matches",
    "html_tag_matches",
    "path_traversal_depth",
    "quote_unbalanced",
    "has_sql_operator",
    "has_ssrf_token",
    "has_ssti_nosql",
    "is_oversized_payload",
    "is_clean_structure",
    "has_excessive_params",
    "method_is_post",
]

# Production contract remains backward-compatible until an extended model
# passes the benign-recall gate and is explicitly promoted.
FEATURE_COLUMNS = BASE_FEATURE_COLUMNS

EXTENDED_FEATURE_COLUMNS = [
    "special_char_count",
    "special_char_ratio",
    "url_path_entropy",
    "suspicious_path_marker_count",
    "query_body_entropy",
    "encoded_char_ratio",
    "double_encoded_count",
    "encoded_attack_token_count",
    "delimiter_count",
    "delimiter_ratio",
    "comment_token_count",
    "inline_function_count",
    "json_operator_count",
    "keyword_matches",
    "html_tag_matches",
    "path_traversal_depth",
    "quote_unbalanced",
    "has_sql_operator",
    "has_ssrf_token",
    "has_ssti_nosql",
    "is_oversized_payload",
    "is_clean_structure",
    "has_excessive_params",
    "method_is_post",
    "is_static_asset",
    "method_is_uncommon",
    "path_depth",
    "max_param_length",
    "param_count",
    "has_duplicate_param_keys",
    "has_control_char_encoding",
    "non_printable_char_count",
    "param_key_has_capital",
    "param_value_punctuation_count",
    "avg_param_length",
    "param_anomaly_score",
]


def feature_columns_for_model(model) -> list:
    """Return the feature column contract the given fitted model was trained on.

    train_model.py fits on EXTENDED_FEATURE_COLUMNS, while older artifacts use
    the 13-column base contract; serving must match whichever was loaded.
    """
    names = getattr(model, "feature_names_in_", None)
    if names is not None:
        return [str(name) for name in names]
    n_features = getattr(model, "n_features_in_", len(FEATURE_COLUMNS))
    if n_features == len(EXTENDED_FEATURE_COLUMNS):
        return EXTENDED_FEATURE_COLUMNS
    return FEATURE_COLUMNS
