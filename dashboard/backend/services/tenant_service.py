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
    """Build ClickHouse SQL fragment for a domain or IP pattern."""
    clean = str(domain_or_ip).strip().lower()
    if not clean or clean == "all":
        return ""
    if "juice" in clean or "3000" in clean:
        return "(url LIKE '%juice%' OR url LIKE '%rest%' OR url LIKE '%socket.io%' OR url LIKE '%assets/public%' OR url LIKE '%main.js%' OR url LIKE '%polyfills.js%' OR url LIKE '%scripts.js%')"
    elif "dvwa" in clean or "8080" in clean or ".php" in clean:
        return "(url LIKE '%dvwa%' OR url LIKE '%.php%' OR url LIKE '%vulnerabilities%')"
    elif "vampi" in clean or "5000" in clean:
        return "(url LIKE '%vampi%' OR url LIKE '%/api/v1/%')"
    elif "bwapp" in clean:
        return "(url LIKE '%bwapp%' OR url LIKE '%bWAPP%')"
    else:
        escaped = escape_like_value(clean)
        return f"(url LIKE '%{escaped}%' OR client_ip LIKE '%{escaped}%')"


def build_tenant_origin_filter(origin: Optional[str], user_domains: List[str], is_admin: bool) -> str:
    """Build a strictly isolated ClickHouse SQL WHERE filter for the current
    tenant/user. Returns "1=0" (matches nothing) rather than "" (matches
    everything) whenever scoping can't be established for a non-admin --
    fail closed, never open."""
    # 1. If a specific origin was requested
    if origin and str(origin).strip().upper() not in ["ALL", ""]:
        req_clean = str(origin).strip()
        if not is_admin and user_domains:
            if not any(req_clean.lower() in d.lower() or d.lower() in req_clean.lower() for d in user_domains):
                return "1=0"  # Forbidden / not this user's domain
        return build_domain_pattern_sql(req_clean)

    # 2. "ALL" (or no origin specified)
    if is_admin:
        return ""  # Admins may see everything when no specific origin is named

    # 3. Standard tenant users: strictly their own registered domains/origins
    if not user_domains:
        return "1=0"  # No registered origins -> no logs, ever

    clauses = [build_domain_pattern_sql(d) for d in user_domains]
    clauses = [c for c in clauses if c]
    return f"({' OR '.join(clauses)})" if clauses else "1=0"


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

        # Collect all domain names registered under user's origins in domains_table
        try:
            all_domains = db.domains_table.scan().get("Items", [])
            user_registered_domains = [
                str(d.get("domain_name")).strip().lower()
                for d in all_domains
                if d.get("origin_id") in origin_ids and d.get("domain_name")
            ]
        except Exception:
            user_registered_domains = []

        # Extract domains/IPs from origin ip/label
        domain_keywords = set(user_registered_domains)
        for o in active_origins:
            ip_val = str(o.get("ip", "")).strip().lower()
            label_val = str(o.get("label", "")).strip().lower()

            if ip_val:
                domain_keywords.add(ip_val)

            if "(" in label_val and ")" in label_val:
                try:
                    extracted = label_val.split("(")[1].split(")")[0].strip()
                    if "." in extracted:
                        domain_keywords.add(extracted.lower())
                except Exception:
                    pass

        result = (origin_ids, active_origins, list(domain_keywords))
        _TENANT_CACHE[user_id] = (now, result)
        return result

    except Exception as e:
        logger.error(f"Error resolving tenant origins for user {user_id}: {e}")
        return [], [], []
