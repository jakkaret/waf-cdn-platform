"""Cross-tenant threat intelligence sharing, opt-in, pattern-only.

Design (2026-09-21), reviewed before writing this:

- The shared unit is (rule_id, attack_type) -- never an IP, URL, or payload.
  A CRS/custom rule_id is already a generic attack-technique identifier
  (e.g. "942100" = SQLi via libinjection detected by ModSecurity's
  libinjection integration), defined once and reused identically across
  every tenant -- it is never victim-specific the way a URL or payload is.
- "Which tenant" contributed a hit is represented only as
  HMAC(THREAT_INTEL_SALT, user_id), truncated to 16 hex chars. This is
  *not reversible without the salt* -- it is not anonymous in an absolute
  sense (a small, known user_id set plus a leaked salt could be brute
  forced), which is why the salt is its own dedicated env var
  (THREAT_INTEL_SALT), never JWT_SECRET_KEY or anything else already
  exposed elsewhere in this codebase.
- Every row in waf_threat_patterns carries an `expires_at` DynamoDB-native
  TTL (confirmed enabled on the table 2026-09-21) -- contributor hashes are
  not retained indefinitely.
- Opt-in is a per-user flag (services.auth_service.set_threat_intel_opt_in),
  read *fresh* (never cached) on every write and every read here. Opt-out
  must be immediate: a stale opt-in that keeps sharing after a user turned
  it off is the actual privacy failure mode, worse than a stale opt-out.
- Reading the trending feed requires the requester to be opted in
  themselves (reciprocity) -- and a pattern only appears once it has been
  seen from at least MIN_DISTINCT_TENANTS distinct contributors, so a
  single opted-in tenant's own traffic is never distinguishable as "the"
  source of a "trending" entry.

Integration seam: record_pattern_hit_for_domain(domain, rule_id,
attack_type) is the one function the alert pipeline calls (from
services/telegram_listener.py's dispatch_telegram_alert, itself already an
async background task -- this adds no latency to the WAF's actual block
response). Domain->owner resolution only covers domains this codebase can
already attribute today: DNS-verified domains_table rows and cloudwaf
tunnel_domains on origins_table (both carry an owner via origin_id/
admin_user_id). A request with no resolvable domain (e.g. a raw nginx
rate-limit block with no ModSecurity match, which carries no Host header in
this pipeline as of 2026-09-21) is silently skipped, not guessed at.
"""
import hashlib
import hmac
import os
import time
import datetime as dt
from typing import Optional, Dict, List

from services.auth_service import AuthService
from services.dynamodb_service import DynamoDBService

db = DynamoDBService()
auth_service = AuthService()

THREAT_INTEL_SALT = os.getenv("THREAT_INTEL_SALT", "")
PATTERN_RETENTION_HOURS = int(os.getenv("THREAT_INTEL_RETENTION_HOURS", "72"))
DEFAULT_WINDOW_HOURS = int(os.getenv("THREAT_INTEL_WINDOW_HOURS", "24"))
MIN_DISTINCT_TENANTS = int(os.getenv("THREAT_INTEL_MIN_DISTINCT_TENANTS", "2"))

_DOMAIN_OWNER_CACHE: Dict[str, str] = {}
_DOMAIN_OWNER_CACHE_AT = 0.0
_DOMAIN_OWNER_CACHE_TTL_SECONDS = 30.0


def _tenant_hash(user_id: str, salt: Optional[str] = None) -> str:
    salt = salt if salt is not None else THREAT_INTEL_SALT
    if not salt:
        # Still functions (never crashes a WAF alert path over a missing
        # env var), but degrades the "not reversible without the salt"
        # property to "not reversible without brute-forcing an empty
        # string", i.e. trivially reversible. Logged once per call
        # deliberately -- loud enough to notice in ops, not so loud it
        # spams every single request.
        print("[threat_intel] WARNING: THREAT_INTEL_SALT is unset -- tenant hashes are effectively reversible")
    digest = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:16]


def _hour_bucket(now: dt.datetime) -> str:
    return now.strftime("%Y%m%d%H")


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def record_pattern_hit(
    user_id: str,
    rule_id: str,
    attack_type: Optional[str],
    db=None,
    now: Optional[dt.datetime] = None,
) -> None:
    """Atomically increments the shared counter for (rule_id, this hour) and
    adds this tenant's hash to the contributor set. Never writes user_id,
    IP, URL, or payload."""
    _db = db if db is not None else globals()["db"]
    now = now or _now_utc()
    bucket = _hour_bucket(now)
    pattern_key = f"{rule_id}#{bucket}"
    expires_at = int((now + dt.timedelta(hours=PATTERN_RETENTION_HOURS)).timestamp())
    tenant_hash = _tenant_hash(user_id)

    _db.threat_patterns_table.update_item(
        Key={"pattern_key": pattern_key},
        # 2026-09-21: every field name goes through an
        # ExpressionAttributeNames placeholder, not written literally --
        # caught live in services/ssl_cert_monitor.py's own persist function
        # that "status" (unrelated field there, but the same UpdateExpression
        # shape) is a DynamoDB reserved word and a bare `field = :v` clause
        # is rejected by real AWS for any reserved name. None of these
        # fields are currently reserved, but aliasing all of them removes
        # the need to know DynamoDB's reserved-word list at all.
        UpdateExpression=(
            "SET #rid = :rid, #at = :at, #tb = :tb, #exp = :exp, #ua = :ua "
            "ADD #hc :one, #th :hashes"
        ),
        ExpressionAttributeNames={
            "#rid": "rule_id",
            "#at": "attack_type",
            "#tb": "time_bucket",
            "#exp": "expires_at",
            "#ua": "updated_at",
            "#hc": "hit_count",
            "#th": "tenant_hashes",
        },
        ExpressionAttributeValues={
            ":rid": rule_id,
            ":at": attack_type,
            ":tb": bucket,
            ":exp": expires_at,
            ":ua": now.isoformat(),
            ":one": 1,
            ":hashes": {tenant_hash},
        },
    )


def get_trending_patterns(
    requesting_user_id: str,
    db=None,
    now: Optional[dt.datetime] = None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    min_distinct_tenants: int = MIN_DISTINCT_TENANTS,
) -> List[dict]:
    """Reciprocity gate: only a tenant who has opted in themselves may read
    the shared feed. Raises PermissionError (mapped to HTTP 403 by the API
    layer) rather than returning an empty list, so "not opted in" is never
    silently confused with "nothing trending right now"."""
    requester = auth_service.get_user_by_id(requesting_user_id)
    if not requester or not requester.get("share_threat_intel"):
        raise PermissionError("Opt in to threat intel sharing to view the community feed")

    _db = db if db is not None else globals()["db"]
    now = now or _now_utc()
    cutoff = now - dt.timedelta(hours=window_hours)

    rows = _db.threat_patterns_table.scan().get("Items", [])
    by_rule: Dict[str, dict] = {}
    for row in rows:
        bucket = row.get("time_bucket")
        if not bucket:
            continue
        try:
            bucket_dt = dt.datetime.strptime(bucket, "%Y%m%d%H").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
        if bucket_dt < cutoff:
            continue

        rule_id = row.get("rule_id")
        agg = by_rule.setdefault(rule_id, {
            "rule_id": rule_id,
            "attack_type": row.get("attack_type"),
            "total_hits": 0,
            "tenant_hashes": set(),
        })
        agg["total_hits"] += int(row.get("hit_count") or 0)
        agg["tenant_hashes"] |= set(row.get("tenant_hashes") or set())

    results = []
    for agg in by_rule.values():
        distinct = len(agg["tenant_hashes"])
        if distinct < min_distinct_tenants:
            continue
        results.append({
            "rule_id": agg["rule_id"],
            "attack_type": agg["attack_type"],
            "total_hits": agg["total_hits"],
            "distinct_tenants": distinct,
            "window_hours": window_hours,
        })

    results.sort(key=lambda r: (r["distinct_tenants"], r["total_hits"]), reverse=True)
    return results


def _build_domain_owner_map(db) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    origin_items = db.origins_table.scan().get("Items", [])
    owner_by_origin_id = {}
    for o in origin_items:
        origin_id = o.get("id")
        owner = o.get("admin_user_id")
        if origin_id and owner:
            owner_by_origin_id[origin_id] = owner
        if owner:
            for d in (o.get("tunnel_domains") or []):
                if d:
                    mapping[str(d).strip().lower()] = owner

    domain_items = db.domains_table.scan().get("Items", [])
    for d in domain_items:
        name = d.get("domain_name")
        owner = owner_by_origin_id.get(d.get("origin_id"))
        if name and owner:
            mapping[str(name).strip().lower()] = owner

    return mapping


def _domain_owner_map(now: Optional[float] = None) -> Dict[str, str]:
    """30s-cached domain->owning-user_id map, mirroring api/domains.py's
    _ssl_allowed_set() caching pattern. Serves a stale map on a transient
    scan failure rather than raising (this is a best-effort attribution
    seam on a background alert path, not a security gate)."""
    global _DOMAIN_OWNER_CACHE, _DOMAIN_OWNER_CACHE_AT
    _now = now if now is not None else time.monotonic()
    if _DOMAIN_OWNER_CACHE and (_now - _DOMAIN_OWNER_CACHE_AT) < _DOMAIN_OWNER_CACHE_TTL_SECONDS:
        return _DOMAIN_OWNER_CACHE
    try:
        _DOMAIN_OWNER_CACHE = _build_domain_owner_map(db)
        _DOMAIN_OWNER_CACHE_AT = _now
    except Exception as e:
        print(f"[threat_intel] domain owner map refresh failed, serving stale: {e}")
    return _DOMAIN_OWNER_CACHE


def record_pattern_hit_for_domain(
    domain: str,
    rule_id: Optional[str],
    attack_type: Optional[str],
    db=None,
    now: Optional[dt.datetime] = None,
) -> None:
    """The real integration seam: resolves `domain` to its owning tenant and
    records a hit only if that tenant is opted in *right now* (fetched
    fresh every call -- never cached -- so opt-out takes effect
    immediately). Never raises: a bad/unknown domain or missing rule_id is a
    silent no-op, since this must never be able to break the alert pipeline
    that calls it."""
    if not domain or not rule_id:
        return
    try:
        owner_map = _domain_owner_map()
        owner_id = owner_map.get(str(domain).strip().lower())
        if not owner_id:
            return
        owner = auth_service.get_user_by_id(owner_id)
        if not owner or not owner.get("share_threat_intel"):
            return
        record_pattern_hit(owner_id, rule_id, attack_type, db=db, now=now)
    except Exception as e:
        print(f"[threat_intel] record_pattern_hit_for_domain failed for {domain!r}: {e}")
