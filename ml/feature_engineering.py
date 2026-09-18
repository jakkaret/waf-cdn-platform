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
ENCODED_BYTE_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
ENCODED_ATTACK_TOKEN_PATTERN = re.compile(r"(?i)%(?:25[0-9a-fA-F]{2}|27|22|3c|3e|2f|5c|60|24|7b|7d|3b|28|29|5b|5d)")
SUSPICIOUS_PATH_MARKER_PATTERN = re.compile(r"(?i)(?:\.bak|\.old|\.inc|\.sql|~)(?:$|[/?#])")

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

    # 1. Entropy on separate URL path and query/body components.
    parsed_url = urllib.parse.urlsplit(decoded_url)
    path_component = parsed_url.path or decoded_url.split("?", 1)[0]
    query_body_component = f"{parsed_url.query} {decoded_body}".strip()
    url_path_entropy = calculate_shannon_entropy(path_component)
    suspicious_path_marker_count = len(SUSPICIOUS_PATH_MARKER_PATTERN.findall(path_component))
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

    # 8. Clean Benign Indicator
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
        is_oversized_payload == 0
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
        "method_is_post": method_is_post
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
]
