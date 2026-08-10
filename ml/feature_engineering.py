import math
import re
import urllib.parse
from typing import Dict, Union, List, Any

# Special characters frequently used in web payloads (SQLi, XSS, Path Traversal, Command Injection)
SPECIAL_CHARS = set("'\"-;--<>*%\\$()=:|&!{}[]`^")

# Attack keywords pattern
ATTACK_KEYWORD_PATTERN = re.compile(
    r"(select|union|insert|update|delete|drop|exec|where|from|or\s+1=1|and\s+1=1|<script|javascript:|alert\(|eval\(|\.\./|\.\.\\)",
    re.IGNORECASE
)

HTML_TAG_PATTERN = re.compile(r"<[^>]+>", re.IGNORECASE)

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
    Automatically decodes URL-encoding for maximum accuracy.
    """
    raw_url = str(url or "")
    raw_body = str(body or "")
    
    # 0. URL Decode for maximum visibility into obfuscated payloads
    decoded_url = urllib.parse.unquote(raw_url)
    decoded_body = urllib.parse.unquote(raw_body)
    
    combined_str = f"{method} {decoded_url} {decoded_body}".strip()
    total_len = max(len(combined_str), 1)

    # 1. Entropy
    url_entropy = calculate_shannon_entropy(decoded_url)
    combined_entropy = calculate_shannon_entropy(combined_str)

    # 2. Special Characters Count & Ratio
    special_char_count = sum(1 for char in combined_str if char in SPECIAL_CHARS)
    special_char_ratio = special_char_count / total_len

    # 3. Request Lengths
    request_length = total_len
    url_length = len(decoded_url)

    # 4. Parameter count
    param_count = decoded_url.count('&') + (1 if '=' in decoded_url else 0)

    # 5. Method
    method_is_post = 1 if method.upper() == "POST" else 0

    # 6. Digit & Uppercase ratio
    digit_count = sum(1 for char in combined_str if char.isdigit())
    digit_ratio = digit_count / total_len

    uppercase_count = sum(1 for char in combined_str if char.isupper())
    uppercase_ratio = uppercase_count / total_len

    # 7. Attack keyword occurrences & HTML tags & Path Traversal
    keyword_matches = len(ATTACK_KEYWORD_PATTERN.findall(combined_str))
    html_tag_matches = len(HTML_TAG_PATTERN.findall(combined_str))
    path_traversal_depth = combined_str.count('../') + combined_str.count('..\\')
    
    quote_single_diff = abs(combined_str.count("'") % 2)
    quote_double_diff = abs(combined_str.count('"') % 2)
    quote_unbalanced = 1 if (quote_single_diff + quote_double_diff) > 0 else 0

    return {
        "url_entropy": round(url_entropy, 4),
        "combined_entropy": round(combined_entropy, 4),
        "special_char_count": special_char_count,
        "special_char_ratio": round(special_char_ratio, 4),
        "request_length": request_length,
        "url_length": url_length,
        "param_count": param_count,
        "method_is_post": method_is_post,
        "digit_ratio": round(digit_ratio, 4),
        "uppercase_ratio": round(uppercase_ratio, 4),
        "keyword_matches": keyword_matches,
        "html_tag_matches": html_tag_matches,
        "path_traversal_depth": path_traversal_depth,
        "quote_unbalanced": quote_unbalanced
    }

FEATURE_COLUMNS = [
    "url_entropy",
    "combined_entropy",
    "special_char_count",
    "special_char_ratio",
    "request_length",
    "url_length",
    "param_count",
    "method_is_post",
    "digit_ratio",
    "uppercase_ratio",
    "keyword_matches",
    "html_tag_matches",
    "path_traversal_depth",
    "quote_unbalanced"
]
