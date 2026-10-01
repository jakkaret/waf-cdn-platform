"""Phase 2 item 3 -- the WAF (ModSecurity + OWASP CRS, PARANOIA 1, anomaly
threshold 10) actually blocks common attacks on a real tenant host, and does
not block ordinary browsing (no false positives on realistic traffic).

Traffic path exercised end to end: client -> edge Caddy -> edge nginx ->
Main waf-nginx:8080 (ModSecurity/CRS) -> frp tunnel -> qa-echo. A 403 here is
the WAF's anomaly block; a JSON body from qa-echo (is_origin_response) means
the request passed the WAF and reached the origin.

The `shield` fixture forces qa1's CAPTCHA/OTP off first, so a 403 can only be
the CRS anomaly block, never a challenge gate, and a benign GET is not turned
into a 401/challenge.
"""
import httpx
import pytest

from conftest import fresh, is_origin_response, site

# path (already URL-safe) -> short label. Each should push the inbound anomaly
# score past the threshold on its own at PL1.
ATTACKS = {
    "sqli_boolean": "/?id=1%27%20OR%20%271%27=%271",
    "sqli_union": "/?id=-1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "xss_script": "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "path_traversal": "/?file=../../../../etc/passwd",
    "cmd_injection": "/?x=1;cat%20/etc/passwd",
}
# A bare SQLi in a *path segment* scores below the CRS threshold at PL1; the
# managed rule 3000006 (modsecurity/managed-rules/002-path-sqli.conf) blocks it.
ATTACKS["sqli_in_path"] = "/products/1%27%20OR%201=1--"

# Ordinary browsing that must sail through untouched.
BENIGN = {
    "root": "/",
    "listing": "/products?category=shoes&sort=price_asc&page=2",
    "search_words": "/search?q=blue+running+shoes",
    "nested_resource": "/api/items/42",
    "apostrophe_in_path": "/blog/don%27t-stop",
    "utf8_query": "/search?q=%E0%B8%A3%E0%B8%AD%E0%B8%87%E0%B9%80%E0%B8%97%E0%B9%89%E0%B8%B2",  # รองเท้า
}


@pytest.fixture()
def waf_only(shield):
    """qa1 with both shield engines off -- isolates CRS from the challenge gate."""
    shield(captcha={"enabled": False}, otp={"enabled": False})


@pytest.mark.parametrize("label,path", list(ATTACKS.items()), ids=list(ATTACKS))
def test_crs_blocks_attacks(waf_only, qa1, label, path):
    with site(qa1["host"]) as c:
        r = c.get(fresh(path))
    assert r.status_code == 403, f"{label}: WAF did not block ({r.status_code}); body head: {r.text[:120]!r}"


@pytest.mark.parametrize("label,path", list(BENIGN.items()), ids=list(BENIGN))
def test_no_false_positive_on_benign_traffic(waf_only, qa1, label, path):
    with site(qa1["host"]) as c:
        r = c.get(fresh(path))
    assert r.status_code != 403, f"{label}: WAF false-positive blocked benign traffic"


def test_benign_request_actually_reaches_origin(waf_only, qa1):
    """Sanity that "not 403" above means "passed to origin", not "origin down
    returning some other error" -- at least the root path must echo back."""
    with site(qa1["host"]) as c:
        r = c.get(fresh("/"))
    if r.status_code in (502, 503, 504):
        pytest.skip(f"qa1 origin/tunnel unavailable ({r.status_code}); WAF pass-through not judgeable")
    assert is_origin_response(r), f"benign root did not reach qa-echo: {r.status_code} {r.text[:120]!r}"
