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
    decoded_url = urllib.parse.unquote(urllib.parse.unquote(raw_url))
    decoded_body = urllib.parse.unquote(urllib.parse.unquote(raw_body))
    
    # Payload content without HTTP method
    payload_str = f"{decoded_url} {decoded_body}".strip()
    payload_len = max(len(payload_str), 1)
    
    combined_str = f"{method} {decoded_url} {decoded_body}".strip()
    total_len = max(len(combined_str), 1)

    # 1. Entropy
    url_entropy = calculate_shannon_entropy(decoded_url)
    combined_entropy = calculate_shannon_entropy(combined_str)

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

    # 7. Clean Benign Indicator
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

FEATURE_COLUMNS = [
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
    "method_is_post"
]
