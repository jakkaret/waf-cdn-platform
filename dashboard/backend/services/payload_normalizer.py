"""
Zero-Overhead Payload Normalization & Evasion Defense Engine
Normalizes and sanitizes malicious input vectors before WAF inspection and explainability analysis.
Defends against:
- Unicode Homoglyphs & Full-width / Half-width Form Evasions (NFKC Normalization)
- Multi-layer / Recursive URL Percent-Encoding (%2527 -> %27 -> ')
- HTML Entity Obfuscation (&#x3c;, &#60;, &lt;)
- Null-byte & Non-printable Control Character Injections (\x00, %00)
- SQL Comment Obfuscation (/**/ -> space)
"""

import re
import html
import urllib.parse
import unicodedata
from typing import Tuple, List, Dict, Any, Union

# Compiled sanitization regexes
RE_NULL_BYTES = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
RE_NULL_ENCODINGS = re.compile(r"(?i)(?:%00|%2500|%252500|\\x00|\\u0000|&#0*0;?|&#x0*0;?)")
RE_SQL_COMMENTS = re.compile(r"/\*[\s\S]*?\*/")
RE_EXCESS_WHITESPACE = re.compile(r"[\s\t\r\n]+")
RE_PERCENT_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")


class PayloadNormalizer:
    """Enterprise-grade normalizer to counter payload evasion and encoding attacks."""

    def __init__(self, max_decode_depth: int = 5):
        self.max_decode_depth = max_decode_depth

    def recursive_url_decode(self, text: str) -> str:
        """
        Recursively unquotes URL-encoded characters up to max_decode_depth.
        Stops early when the string becomes idempotent to prevent CPU denial of service.
        """
        if not text or "%" not in text:
            return text

        current = text
        for _ in range(self.max_decode_depth):
            if not RE_PERCENT_ENCODED.search(current):
                break
            try:
                decoded = urllib.parse.unquote(current)
                if decoded == current:
                    break
                current = decoded
            except Exception:
                break
        return current

    def normalize_unicode(self, text: str) -> str:
        """
        Applies Unicode NFKC (Compatibility Decomposition followed by Canonical Composition).
        Converts full-width characters (e.g. ＜ ｓ ｃ ｒ ｉ ｐ ｔ ＞ U+FF1C..) to standard ASCII (<script>).
        Preserves natural language characters like Thai (ภาษาไทย), Cyrillic, CJK, etc.
        """
        if not text:
            return ""
        return unicodedata.normalize("NFKC", text)

    def normalize_html_entities(self, text: str) -> str:
        """Unescapes HTML numeric and named entities (e.g., &#x3c; -> <, &amp; -> &)"""
        if not text or ("&" not in text and "&#" not in text):
            return text
        try:
            return html.unescape(text)
        except Exception:
            return text

    def strip_null_and_control_chars(self, text: str) -> str:
        """Removes null bytes, encoded null representations (%2500, %00, \x00), and dangerous ASCII control characters."""
        if not text:
            return ""
        cleaned = RE_NULL_ENCODINGS.sub("", text)
        cleaned = cleaned.replace("\x00", "").replace("%00", "").replace("%08", "")
        return RE_NULL_BYTES.sub("", cleaned)

    def collapse_sql_comments(self, text: str) -> str:
        """Replaces inline SQL comments (/**/) with single space to defeat keyword splitting evasion."""
        if not text or "/*" not in text:
            return text
        return RE_SQL_COMMENTS.sub(" ", text)

    def normalize_string(self, text: str, preserve_case: bool = False) -> str:
        """
        Full multi-stage normalization pipeline for an arbitrary string:
        1. Pre-decode null-byte and encoded null (%2500, %00) stripping
        2. Recursive URL percent-decoding (up to max_decode_depth)
        3. Post-URL-decode null-byte stripping (defeats %2500 -> %00 -> \x00 evasion)
        4. HTML entity unescaping
        5. Post-HTML-decode null-byte stripping
        6. Unicode NFKC Canonical Normalization
        7. Secondary URL decode + null stripping after Unicode expansion
        8. Inline SQL comment collapsing
        9. Final null-byte and control character elimination pass
        """
        if not text or not isinstance(text, str):
            return text or ""

        # Step 1: Initial null-byte & control chars strip
        s = self.strip_null_and_control_chars(text)

        # Step 2: Recursive URL decode
        s = self.recursive_url_decode(s)

        # Step 3: Post URL decode strip (handles double-encoded null %2500 -> %00 -> \x00)
        s = self.strip_null_and_control_chars(s)

        # Step 4: HTML entity unescape
        s = self.normalize_html_entities(s)
        s = self.strip_null_and_control_chars(s)

        # Step 5: Unicode normalization (NFKC)
        s = self.normalize_unicode(s)
        s = self.strip_null_and_control_chars(s)

        # Step 6: Secondary URL decode after Unicode expansion
        if "%" in s:
            s = self.recursive_url_decode(s)
            s = self.strip_null_and_control_chars(s)

        # Step 7: SQL comment collapsing
        s = self.collapse_sql_comments(s)

        # Step 8: Final sanitization pass
        s = self.strip_null_and_control_chars(s)

        # Step 9: Case handling if requested
        if not preserve_case:
            s = s.strip()

        return s

    def normalize_dict_or_payload(self, data: Union[Dict, List, str, Any]) -> Any:
        """Recursively normalizes all strings inside structured JSON/Dict payloads."""
        if isinstance(data, dict):
            return {k: self.normalize_dict_or_payload(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.normalize_dict_or_payload(item) for item in data]
        elif isinstance(data, str):
            return self.normalize_string(data)
        return data


# Global singleton instance
payload_normalizer = PayloadNormalizer()
