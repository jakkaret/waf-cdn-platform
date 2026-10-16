"""Main's request rate limiter (P2.6, R1).

The rules an admin sets on the dashboard (waf.rate_limit_rules) never reached
real traffic: nginx called the old limiter (dashboard /api/limiter/check)
with an auth_request inside the shield's own auth_request subrequest, and
nginx does not run auth_request in a subrequest. nginx allows one
auth_request per location, so the limit is now checked here, as the first
step of the shield check that every proxied location already makes.

The dashboard publishes the enabled rules to Redis (RULES_KEY, see
dashboard/backend/services/rate_limit_service.py). Every rule that matches a
request counts it in its own window, per client IP:
rate:limit:<rule id>:<ip>. Going over any of them answers 429.

Fails open (request allowed) when Redis or the rules are unavailable, like
the limiter it replaces.
"""
import json
import logging
import re
import time

from shield_paths import normalize_path

logger = logging.getLogger(__name__)

RULES_KEY = "waf:ratelimit:rules"
KEY_PREFIX = "rate:limit:"
RULES_CACHE_SECONDS = 5

# Never throttled: the page's own assets (same list as the old limiter).
_STATIC_RE = re.compile(
    r"\.(css|js|jsx|ts|tsx|jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|eot|otf|json|map|txt|xml|mp4|webm)$"
)
_STATIC_PREFIXES = ("/assets/", "/static/")

_cache = {"at": 0.0, "rules": []}


def is_static_asset(path: str) -> bool:
    return path.startswith(_STATIC_PREFIXES) or bool(_STATIC_RE.search(path))


def _rules(client) -> list:
    now = time.monotonic()
    if now - _cache["at"] < RULES_CACHE_SECONDS:
        return _cache["rules"]
    try:
        raw = client.get(RULES_KEY)
        rules = json.loads(raw) if raw else []
        if not isinstance(rules, list):
            rules = []
    except Exception as exc:
        logger.warning("rate limit rules unavailable, keeping the previous set: %s", exc)
        return _cache["rules"]
    _cache.update(at=now, rules=rules)
    return rules


def _matches(rule: dict, method: str, path: str) -> bool:
    if not rule.get("enabled", 1):
        return False
    rule_method = str(rule.get("method") or "ALL").upper()
    if rule_method != "ALL" and rule_method != method:
        return False
    pattern = str(rule.get("path_pattern") or "*").strip().lower()
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _count(client, key: str, window: int) -> tuple:
    """(requests in this window, seconds left). One MULTI so the key always
    gets its expiry together with its first count."""
    pipe = client.pipeline(transaction=True)
    pipe.set(key, 0, ex=window, nx=True)
    pipe.incr(key)
    pipe.ttl(key)
    _, count, ttl = pipe.execute()
    return int(count), int(ttl)


def check(client, method: str, raw_uri: str, ip: str) -> tuple:
    """(allowed, retry_after seconds)."""
    if client is None:
        return True, 0
    method = (method or "GET").upper()
    if method == "OPTIONS":
        return True, 0
    path = normalize_path(raw_uri)
    if is_static_asset(path):
        return True, 0
    retry_after = 0
    try:
        for rule in _rules(client):
            if not _matches(rule, method, path):
                continue
            limit = max(1, int(rule.get("limit_count") or 1))
            window = max(1, int(rule.get("window_seconds") or 1))
            count, ttl = _count(client, f"{KEY_PREFIX}{rule.get('id')}:{ip}", window)
            if count > limit:
                retry_after = max(retry_after, ttl if ttl > 0 else window)
    except Exception as exc:
        logger.warning("rate limit check failed, allowing: %s", exc)
        return True, 0
    return retry_after == 0, retry_after
