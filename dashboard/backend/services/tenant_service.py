import time
import logging
from typing import List, Dict, Tuple, Optional
from services.dynamodb_service import DynamoDBService
from services.clickhouse_service import escape_like_value

logger = logging.getLogger(__name__)
db = DynamoDBService()

_TENANT_CACHE: Dict[str, Tuple[float, Tuple[List[str], List[Dict], List[str]]]] = {}
CACHE_TTL = 3.0  # 3 seconds cache


def invalidate_tenant_cache(user_id: Optional[str] = None):
    global _TENANT_CACHE
    if user_id:
        _TENANT_CACHE.pop(user_id, None)
    else:
        _TENANT_CACHE.clear()


# 2026-09-20 fix: moved here from api/analytics.py (the only router that had
# them) so api/copilot.py and api/ai_summary.py can share the exact same
# tenant-isolation logic instead of querying ClickHouse's access_logs table
# with no WHERE clause at all -- confirmed live: a brand-new account with
# zero registered origins asking the AI Copilot "which IPs are attacking me"
# got back real attacker IPs, real attack payloads and real timestamps
# belonging to other tenants' traffic, because the ClickHouse queries feeding
# its prompt context had no tenant filter whatsoever (unlike this file's own
# get_user_origins_and_domains, which every one of these three routers
# already called correctly for the *domain list* -- only the log queries
# themselves were unscoped).
def build_domain_pattern_sql(domain_or_ip: str) -> str:
    """ClickHouse SQL fragment matching one domain's traffic: exact equality
    on access_logs.host, nothing else.

    Until 2026-10-16 rows with host = '' were matched by guessing the origin
    from URL keywords ('%.php%' for anything DVWA-like, '%<domain>%' in the
    URL or client IP), which could hand one tenant another tenant's traffic
    (N18/H44/H49). Production held no such rows, writers now store "-" for a
    missing Host (clickhouse_service.UNKNOWN_HOST), and the guess is gone.
    """
    clean = str(domain_or_ip).strip().lower()
    if not clean or clean == "all":
        return ""
    return f"(host = '{escape_like_value(clean)}')"


def _normalize_origin_key(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def is_origin_owned(requested: str, user_domains: List[str]) -> bool:
    """True only when `requested` is exactly one of the user's domains/IPs.

    2026-09-28: this used to be a two-way substring test
    (`req in d or d in req`), so a tenant owning "shop.example.com" could ask
    for origin="example.com" (or "shop.example.co", "e.com", ...) and have
    the query run as host = '<what they asked for>' -- another tenant's
    traffic. The origin selector only ever sends a value taken verbatim from
    the user's own origins, so exact matching costs legitimate use nothing.
    """
    req = _normalize_origin_key(requested)
    return bool(req) and any(req == _normalize_origin_key(d) for d in user_domains or [])


# Platform admins (the support team) see a tenant's logs, analytics and
# alerts only while that tenant's origin has an active support grant
# (docs/tickets/support-access.md). Traffic that belongs to no tenant (the
# platform's own hosts, unknown Host "-") stays visible to them.
_ADMIN_SCOPE_CACHE: Dict[str, Tuple[float, tuple]] = {}


def admin_log_scope() -> Tuple[set, set, set, set]:
    """(tenant_hosts, granted_hosts, tenant_origin_ids, granted_origin_ids).
    tenant_hosts covers every origin in any status, verified or not, so a
    host never counts as "nobody's" just because its owner has not verified
    it yet. Raises if the store is unreachable; callers fail closed."""
    now = time.time()
    hit = _ADMIN_SCOPE_CACHE.get("v")
    if hit and now - hit[0] < CACHE_TTL:
        return hit[1]
    from db import pool
    rows = pool.q("SELECT lower(rtrim(hostname, '.')) AS host, origin_id::text AS origin_id FROM origin_hostnames")
    origin_ids = {r["origin_id"] for r in pool.q("SELECT id::text AS origin_id FROM origins")}
    granted_ids = {r["origin_id"] for r in pool.q(
        "SELECT DISTINCT origin_id::text AS origin_id FROM support_grants "
        "WHERE revoked_at IS NULL AND expires_at > now()")}
    tenant_hosts = {r["host"] for r in rows if r["host"]}
    granted_hosts = {r["host"] for r in rows if r["host"] and r["origin_id"] in granted_ids}
    val = (tenant_hosts, granted_hosts, origin_ids, granted_ids)
    _ADMIN_SCOPE_CACHE["v"] = (now, val)
    return val


def invalidate_admin_scope_cache() -> None:
    _ADMIN_SCOPE_CACHE.clear()


def _admin_filter(origin: Optional[str]) -> str:
    try:
        tenant_hosts, granted_hosts, _ids, _gids = admin_log_scope()
    except Exception as exc:
        logger.warning("admin log scope unavailable, failing closed: %s", exc)
        return "1=0"
    blocked = sorted(tenant_hosts - granted_hosts)
    if origin and str(origin).strip().upper() not in ["ALL", ""]:
        req = _normalize_origin_key(origin)
        if req in blocked:
            return "1=0"  # a tenant's host with no active support grant
        return build_domain_pattern_sql(req)
    if not blocked:
        return ""
    hosts = ", ".join(f"'{escape_like_value(h)}'" for h in blocked)
    return f"(host NOT IN ({hosts}))"


def build_tenant_origin_filter(origin: Optional[str], user_domains: List[str], is_admin: bool) -> str:
    """Build a strictly isolated ClickHouse SQL WHERE filter for the current
    tenant/user. Returns "1=0" (matches nothing) rather than "" (matches
    everything) whenever scoping can't be established -- fail closed, never
    open. A platform admin sees non-tenant traffic plus the tenants that
    currently grant support access (_admin_filter)."""
    if is_admin:
        return _admin_filter(origin)

    # 1. If a specific origin was requested
    if origin and str(origin).strip().upper() not in ["ALL", ""]:
        req_clean = str(origin).strip()
        # Also covers a user with no domains at all: that used to skip the
        # check entirely and query whatever origin was asked for.
        if not is_origin_owned(req_clean, user_domains):
            return "1=0"  # Forbidden / not this user's domain
        # Same normalisation as the ownership check and as access_logs.host
        # (normalize_host drops the root-label dot).
        return build_domain_pattern_sql(_normalize_origin_key(req_clean))

    # 3. Standard tenant users: strictly their own registered domains/origins
    if not user_domains:
        return "1=0"  # No registered origins -> no logs, ever

    clauses = [build_domain_pattern_sql(d) for d in user_domains]
    clauses = [c for c in clauses if c]
    return f"({' OR '.join(clauses)})" if clauses else "1=0"


def verified_scope_keywords(origins: List[Dict], domain_rows: List[Dict]) -> set:
    """Hostnames allowed to scope a tenant's log / analytics / alert rows.

    Only provably-owned channels count: domain rows proven through DNS
    verification (``dns_verified``) and ``tunnel_domains`` recorded on the
    origin by the tunnel gatekeeper. An origin's self-typed ``ip`` and the
    ``(domain)`` inside its ``label`` are deliberately excluded -- both are
    free text the tenant controls, so trusting them lets one tenant type
    another tenant's hostname into their own origin and read that tenant's
    rows. Mirrors the SSL allowlist (api/domains.py::_load_ssl_allowed_from_db).
    """
    kw = set()
    for d in domain_rows or []:
        if d.get("domain_name") and d.get("dns_verified", False):
            kw.add(str(d["domain_name"]).strip().lower())
    for o in origins or []:
        for td in (o.get("tunnel_domains") or []):
            if td:
                kw.add(str(td).strip().lower())
    return kw


def get_user_origins_and_domains(user_id: str) -> Tuple[List[str], List[Dict], List[str]]:
    """
    Retrieve strictly isolated origins and domains owned by a specific user,
    cached in-memory for 3 seconds to avoid multi-second AWS DynamoDB WAN roundtrip latency.
    """
    if not user_id:
        return [], [], []

    now = time.time()
    if user_id in _TENANT_CACHE:
        cached_time, cached_val = _TENANT_CACHE[user_id]
        if now - cached_time < CACHE_TTL:
            return cached_val

    try:
        # Deferred import: origin_service imports invalidate_tenant_cache
        # from this module, so a module-level import here would be circular.
        # get_origins_visible_to_user() = owned origins UNION origins this
        # user was explicitly granted viewer access to -- a viewer grant
        # extends into logs/analytics isolation too, not just the Origins
        # list, matching the intended "owner decides who else can see it"
        # design.
        from services.origin_service import get_origins_visible_to_user
        user_origins = get_origins_visible_to_user(user_id)
        if not user_origins:
            result = ([], [], [])
            _TENANT_CACHE[user_id] = (now, result)
            return result

        active_origins = [o for o in user_origins if o.get("status") != "archived" and o.get("status") != "deleted"]
        if not active_origins:
            result = ([], [], [])
            _TENANT_CACHE[user_id] = (now, result)
            return result

        origin_ids = [str(o.get("id")) for o in active_origins if o.get("id")]

        # Collect all domain names registered under user's origins.
        # Indexed lookup per origin rather than a full-table scan: this runs
        # on every analytics/logs/copilot request behind a 3s cache, and the
        # scan it replaces both read every other tenant's rows and silently
        # truncated at DynamoDB's 1MB response cap without paginating.
        try:
            domain_rows = db.get_domains_by_origin_ids(origin_ids)
        except Exception:
            domain_rows = []

        # Scope keywords come only from DNS-verified domains and tunnel
        # domains -- never the origin's self-typed ip/label, which a tenant
        # could set to another tenant's hostname to read their rows.
        domain_keywords = verified_scope_keywords(active_origins, domain_rows)

        result = (origin_ids, active_origins, sorted(domain_keywords))
        _TENANT_CACHE[user_id] = (now, result)
        return result

    except Exception as e:
        logger.error(f"Error resolving tenant origins for user {user_id}: {e}")
        return [], [], []
