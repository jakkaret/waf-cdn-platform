"""Phase 2 of the remediation plan (security audit run 1): shield coverage,
config ownership, cookie key and lifetime, real client IP, rate limiter and
behaviour while Redis is down.

    cd cdn/control-api && python -m pytest tests -q
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import captcha_engine  # noqa: E402
import otp_engine  # noqa: E402
import rate_limit  # noqa: E402
from shield_paths import is_protected, normalize_path  # noqa: E402
from test_shield import FakeRedis, HOST, ORIGIN, check, client, enable, redis_  # noqa: E402,F401


# ------------------------------------------------ P2.1 every spelling of a path

BYPASS_SPELLINGS = [
    "/login",
    "/LOGIN",
    "/Login",
    "/%6cogin",
    "/%256cogin",            # double-encoded
    "//login",
    "///login",
    "/./login",
    "/static/../login",
    "/static/%2e%2e/login",
    "/static%2f..%2flogin",
    "\\login",
    "/login;jsessionid=abc",
    "/login/",
    "/login?next=/",
    "/login#frag",
    "/login.php",            # matched by /login*
]


@pytest.mark.parametrize("uri", BYPASS_SPELLINGS)
def test_every_spelling_of_a_protected_path_is_protected(uri):
    assert is_protected(uri, ["/login*"])


@pytest.mark.parametrize("uri", BYPASS_SPELLINGS)
@pytest.mark.parametrize("kind", ["captcha", "otp"])
def test_every_spelling_gets_the_challenge(client, redis_, kind, uri):
    enable(redis_, kind)
    resp = check(client, "GET", uri)
    assert resp.status_code == 401, uri
    assert resp.headers["X-Shield-Type"] == kind


@pytest.mark.parametrize("uri", ["/products", "/blog/login-tips", "/static/app.css", "/"])
def test_other_paths_are_not_protected(uri):
    assert not is_protected(uri, ["/login*", "/admin*"])


def test_exclusion_still_works_and_cannot_be_used_to_reach_a_protected_path():
    login, exclude = ["/wp-admin*"], ["/wp-admin/admin-ajax.php"]
    assert not is_protected("/wp-admin/admin-ajax.php", login, exclude)
    assert not is_protected("/WP-ADMIN/Admin-Ajax.php", login, exclude)
    assert is_protected("/wp-admin/admin-ajax.php/../index.php", login, exclude)
    assert is_protected("/wp-admin/", login, exclude)


def test_normalize_path():
    assert normalize_path("/A//b/./c/../D?x=1") == "/a/b/d"
    assert normalize_path("/../../etc") == "/etc"
    assert normalize_path("") == "/"


# --------------------------------- P2.2 a key counts only for its current owner

@pytest.mark.parametrize("kind", ["captcha", "otp"])
def test_key_left_by_a_previous_owner_is_ignored(client, redis_, kind):
    enable(redis_, kind)
    redis_.hset(captcha_engine.HOSTMAP_KEY, HOST, "someone-else")
    assert check(client, "GET").status_code == 204


@pytest.mark.parametrize("kind", ["captcha", "otp"])
def test_key_for_a_host_no_longer_verified_is_ignored(client, redis_, kind):
    enable(redis_, kind)
    redis_.hashes[captcha_engine.HOSTMAP_KEY].pop(HOST)
    assert check(client, "GET").status_code == 204


def test_config_matches_the_host_whatever_its_spelling(client, redis_):
    enable(redis_, "captcha")
    headers = {"X-Original-Method": "GET", "X-Original-URI": "/login", "X-Original-Host": "SHOP.Example.com.:443",
               "X-Original-IP": "198.51.100.7", "X-Original-User-Agent": "pytest"}
    assert client.get("/api/shield/access", headers=headers).status_code == 401


# ------------------------------------------- P2.4 own key, bounded lifetime

def _captcha_cookie(expiry: int, ip="198.51.100.7", ua="pytest"):
    message = "\x1f".join([captcha_engine.subnet_identity(ip), ua, HOST, str(expiry)])
    sig = hmac.new(captcha_engine.HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{captcha_engine.COOKIE_NAME}={expiry}.{HOST}.{sig}"


def test_captcha_cookie_within_its_ttl_passes(client, redis_):
    enable(redis_, "captcha", clearance_ttl=3600)
    assert check(client, "GET", cookie=_captcha_cookie(int(time.time()) + 3000)).status_code == 204


def test_captcha_cookie_claiming_more_than_the_ttl_is_refused(client, redis_):
    enable(redis_, "captcha", clearance_ttl=3600)
    far = int(time.time()) + 30 * 86400
    assert check(client, "GET", cookie=_captcha_cookie(far)).status_code == 401


def test_otp_cookie_claiming_more_than_the_ttl_is_refused(client, redis_):
    enable(redis_, "otp", clearance_ttl=3600)
    expiry, sid = str(int(time.time()) + 30 * 86400), "a" * 32
    message = "\x1f".join([captcha_engine.subnet_identity("198.51.100.7"), "pytest", HOST, expiry, sid])
    sig = hmac.new(otp_engine.HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    cookie = f"{otp_engine.COOKIE_NAME}={expiry}.{HOST}.{sid}.{sig}"
    assert check(client, "GET", cookie=cookie).status_code == 401


def test_captcha_and_otp_keys_are_separate():
    assert captcha_engine.HMAC_SECRET != otp_engine.HMAC_SECRET


def _import_with(env: dict) -> subprocess.CompletedProcess:
    clean = {k: v for k, v in os.environ.items() if not k.endswith("_HMAC_SECRET") and k != "CONTROL_TOKEN"}
    clean.update(env)
    return subprocess.run([sys.executable, "-c", "import otp_engine"], cwd=HERE, env=clean,
                          capture_output=True, text=True)


@pytest.mark.parametrize("env", [
    {},                                                           # nothing set
    {"CAPTCHA_HMAC_SECRET": "x" * 40},                            # OTP key missing
    {"CAPTCHA_HMAC_SECRET": "short", "OTP_HMAC_SECRET": "y" * 40},
    {"CONTROL_TOKEN": "z" * 40, "CAPTCHA_HMAC_SECRET": "z" * 40, "OTP_HMAC_SECRET": "y" * 40},
])
def test_service_does_not_start_without_its_own_keys(env):
    result = _import_with(env)
    assert result.returncode != 0
    assert "HMAC_SECRET must" in result.stderr


def test_service_starts_with_both_keys():
    assert _import_with({"CAPTCHA_HMAC_SECRET": "x" * 40, "OTP_HMAC_SECRET": "y" * 40}).returncode == 0


# --------------------------------------------- P2.5 IP headers from nginx only

def test_ip_header_from_an_untrusted_caller_is_ignored(monkeypatch):
    from starlette.requests import Request
    monkeypatch.setattr(captcha_engine, "_TRUSTED_PROXIES", ["172.18.0.5"])
    monkeypatch.setattr(captcha_engine, "_trusted_cache", {"at": None, "nets": [], "names": set()})

    def req(peer):
        return Request({"type": "http", "method": "GET", "path": "/", "client": (peer, 1),
                        "headers": [(b"x-original-ip", b"203.0.113.50"), (b"x-real-ip", b"203.0.113.51")]})

    assert captcha_engine.client_ip(req("172.18.0.5")) == "203.0.113.50"
    assert captcha_engine.client_ip(req("10.88.0.2")) == "10.88.0.2"
    assert captcha_engine.client_ip(req("172.18.0.1")) == "172.18.0.1"


# ------------------------------------------------------- P2.6 rate limiter

RULES = [
    {"id": "rule_auth", "path_pattern": "/api/auth/*", "method": "POST", "limit_count": 2, "window_seconds": 60, "enabled": 1},
    {"id": "rule_all", "path_pattern": "*", "method": "ALL", "limit_count": 5, "window_seconds": 1, "enabled": 1},
    {"id": "rule_off", "path_pattern": "*", "method": "ALL", "limit_count": 1, "window_seconds": 60, "enabled": 0},
]


def _limited(redis_, rules=RULES):
    redis_.set(rate_limit.RULES_KEY, json.dumps(rules))
    redis_.hset(rate_limit.HOSTMAP_KEY, HOST, ORIGIN)  # HOST is a site's host


def test_over_the_limit_gets_429_with_retry_after(client, redis_):
    _limited(redis_)
    codes = [check(client, "POST", "/api/auth/login").status_code for _ in range(3)]
    assert codes == [204, 204, 401]
    last = check(client, "POST", "/api/auth/login")
    assert last.headers["X-Shield-Type"] == "ratelimit"
    assert int(last.headers["Retry-After"]) > 0
    assert f"rate:limit:rule_auth:{HOST}|198.51.100.7" in redis_.kv


def test_each_rule_counts_in_its_own_bucket(client, redis_):
    _limited(redis_)
    for _ in range(2):
        assert check(client, "POST", "/api/auth/login").status_code == 204
    # rule_all has its own count (2 so far), its 1 s window is untouched by rule_auth's 60 s one.
    assert redis_.kv[f"rate:limit:rule_all:{HOST}|198.51.100.7"] == 2
    assert redis_.ttls[f"rate:limit:rule_auth:{HOST}|198.51.100.7"] == 60


def test_disabled_rules_static_assets_and_preflight_are_not_counted(client, redis_):
    _limited(redis_, [r for r in RULES if r["id"] == "rule_off"])
    assert check(client, "GET", "/").status_code == 204
    _limited(redis_, [dict(RULES[1], limit_count=1)])
    rate_limit._cache["at"] = -1e9
    for _ in range(5):
        assert check(client, "GET", "/assets/app.js").status_code == 204
        assert check(client, "OPTIONS", "/").status_code == 204


def test_limiter_counts_the_real_client_not_the_caller(client, redis_):
    _limited(redis_, [dict(RULES[1], limit_count=1, window_seconds=60)])
    assert check(client, "GET", "/").status_code == 204
    headers = {"X-Original-Method": "GET", "X-Original-URI": "/", "X-Original-Host": HOST,
               "X-Original-IP": "198.51.100.99", "X-Original-User-Agent": "pytest"}
    assert client.get("/api/shield/access", headers=headers).status_code == 204


def test_limiter_fails_open_without_redis():
    assert rate_limit.check(None, "GET", "/", "198.51.100.7") == (True, 0)


# ------------------------------------------------- P2.3 protected => no-store

def test_protected_path_is_marked_for_no_store(client, redis_):
    enable(redis_, "captcha")
    ok = check(client, "GET", cookie=_captcha_cookie(int(time.time()) + 600))
    assert ok.status_code == 204 and ok.headers.get("X-Shield-Protected") == "1"
    assert "X-Shield-Protected" not in check(client, "GET", "/products").headers


# ------------------------------------------ P2.7 H83 Redis down, H10 ML retry

@pytest.mark.parametrize("kind", ["captcha", "otp"])
def test_protected_path_is_not_opened_when_redis_goes_down(client, redis_, monkeypatch, kind):
    enable(redis_, kind)
    assert check(client, "GET").status_code == 401  # config seen while Redis was up
    for module in (captcha_engine, otp_engine):
        monkeypatch.setattr(module, "_redis", lambda: None)
    for method in ("GET", "POST"):
        resp = check(client, method)
        assert (resp.status_code, resp.headers["X-Shield-Type"]) == (401, "unavailable")
    assert check(client, "GET", "/products").status_code == 204


def test_captcha_clearance_still_passes_while_redis_is_down(client, redis_, monkeypatch):
    enable(redis_, "captcha")
    check(client, "GET")
    for module in (captcha_engine, otp_engine):
        monkeypatch.setattr(module, "_redis", lambda: None)
    assert check(client, "GET", cookie=_captcha_cookie(int(time.time()) + 600)).status_code == 204


def test_log_only_gate_stays_open_when_redis_goes_down(client, redis_, monkeypatch):
    enable(redis_, "captcha", mode="log_only")
    check(client, "GET")
    for module in (captcha_engine, otp_engine):
        monkeypatch.setattr(module, "_redis", lambda: None)
    assert check(client, "GET").status_code == 204


def test_host_never_seen_enabled_is_not_blocked_when_redis_is_down(client, redis_, monkeypatch):
    for module in (captcha_engine, otp_engine):
        monkeypatch.setattr(module, "_redis", lambda: None)
    assert check(client, "GET").status_code == 204


def test_ml_challenge_skips_a_visitor_with_clearance(client, redis_, monkeypatch):
    async def ml(_request):
        return "challenge"

    monkeypatch.setattr(otp_engine, "ml_access_decision", ml)
    assert check(client, "GET", "/products").headers["X-Shield-Type"] == "ml"
    passed = check(client, "GET", "/products", cookie=_captcha_cookie(int(time.time()) + 600))
    assert passed.status_code == 204


# ------------------------------------------------ challenge route statuses

@pytest.fixture()
def main_app(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTROL_DATA_DIR", str(tmp_path))
    import main
    return TestClient(main.app)


def test_challenge_route_answers_429_for_rate_limit(main_app):
    resp = main_app.get("/cdn-cgi/challenge", headers={"X-Shield-Type": "ratelimit", "X-Retry-After": "17"})
    assert resp.status_code == 429 and resp.headers["Retry-After"] == "17"
    bad = main_app.get("/cdn-cgi/challenge", headers={"X-Shield-Type": "ratelimit", "X-Retry-After": "1\r\nX: y"})
    assert bad.headers["Retry-After"] == "60"


def test_challenge_route_answers_503_when_the_store_is_down(main_app):
    resp = main_app.get("/cdn-cgi/challenge", headers={"X-Shield-Type": "unavailable"})
    assert resp.status_code == 503 and resp.headers["Cache-Control"] == "no-store"


# ------------------------------------------ inline ML gate: challenge band

def _clearance(main_app, cookie=""):
    headers = {"X-Original-Host": HOST, "X-Original-IP": "198.51.100.7", "X-Original-User-Agent": "pytest"}
    if cookie:
        headers["Cookie"] = cookie
    return main_app.get("/api/ml/clearance", headers=headers)


def test_ml_clearance_is_204_only_for_this_visitors_valid_cookie(main_app, redis_):
    assert _clearance(main_app).status_code == 401
    good = _clearance(main_app, _captcha_cookie(int(time.time()) + 600))
    assert good.status_code == 204 and good.headers["Cache-Control"] == "no-store"
    assert _clearance(main_app, _captcha_cookie(int(time.time()) - 5)).status_code == 401
    # Issued to another address: not this visitor's clearance.
    assert _clearance(main_app, _captcha_cookie(int(time.time()) + 600, ip="203.0.113.9")).status_code == 401
    assert _clearance(main_app, _captcha_cookie(int(time.time()) + 600, ua="other")).status_code == 401


# 2026-10-25: a site's own rate limits (origin_id) apply only to that site's
# hosts, and every bucket is per host as well as per client IP.

def _site_request(client, host, path="/api/x"):
    headers = {"X-Original-Method": "GET", "X-Original-URI": path, "X-Original-Host": host,
               "X-Original-IP": "198.51.100.7", "X-Original-User-Agent": "pytest"}
    return client.get("/api/shield/access", headers=headers)


def test_a_sites_rule_counts_only_that_sites_hosts(client, redis_):
    redis_.hset(rate_limit.HOSTMAP_KEY, HOST, ORIGIN)
    redis_.hset(rate_limit.HOSTMAP_KEY, "other.example.com", "origin-2")
    _limited(redis_, [{"id": "rule_site", "path_pattern": "/api/*", "method": "ALL", "limit_count": 1,
                       "window_seconds": 60, "enabled": 1, "origin_id": ORIGIN}])
    rate_limit._cache["at"] = -1e9
    assert _site_request(client, HOST).status_code == 204
    assert _site_request(client, HOST).status_code == 401           # over this site's limit
    for _ in range(3):
        assert _site_request(client, "other.example.com").status_code == 204  # another site: not counted
    assert not [k for k in redis_.kv if k.startswith("rate:limit:rule_site:other.example.com")]


def test_platform_rules_count_each_site_on_its_own(client, redis_):
    redis_.hset(rate_limit.HOSTMAP_KEY, HOST, ORIGIN)
    redis_.hset(rate_limit.HOSTMAP_KEY, "other.example.com", "origin-2")
    _limited(redis_, [{"id": "rule_flood", "path_pattern": "*", "method": "ALL", "limit_count": 1,
                       "window_seconds": 60, "enabled": 1}])
    rate_limit._cache["at"] = -1e9
    assert _site_request(client, HOST, "/").status_code == 204
    assert _site_request(client, "other.example.com", "/").status_code == 204   # its own bucket
    assert _site_request(client, HOST, "/").status_code == 401
    assert redis_.kv["rate:limit:rule_flood:other.example.com|198.51.100.7"] == 1


def test_made_up_hosts_share_one_bucket(client, redis_):
    # A Host header that is no site's host cannot open a fresh bucket.
    _limited(redis_, [{"id": "rule_flood", "path_pattern": "*", "method": "ALL", "limit_count": 2,
                       "window_seconds": 60, "enabled": 1}])
    rate_limit._cache["at"] = -1e9
    codes = [_site_request(client, f"random-{i}.invalid", "/").status_code for i in range(3)]
    assert codes == [204, 204, 401]
    assert redis_.kv["rate:limit:rule_flood:-|198.51.100.7"] == 3
