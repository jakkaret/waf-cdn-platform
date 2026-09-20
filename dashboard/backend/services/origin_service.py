import uuid
import re
import os
import time
import httpx
import logging
from typing import List, Dict, Optional, Any, Set, Tuple
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.tenant_service import invalidate_tenant_cache
from services.auth_service import AuthService

logger = logging.getLogger(__name__)
db = DynamoDBService()
auth_service = AuthService()

# Configurable quota — set ORIGINS_QUOTA_DEFAULT in .env to override
ORIGINS_QUOTA_DEFAULT = int(os.getenv("ORIGINS_QUOTA_DEFAULT", "10"))
DOMAINS_QUOTA_PER_ORIGIN = int(os.getenv("DOMAINS_QUOTA_PER_ORIGIN", "10"))

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")
FRP_ADMIN_USER = os.getenv("FRP_ADMIN_USER", "admin")
FRP_ADMIN_PASS = os.getenv("FRP_ADMIN_PASS", "admin1234")

# Live FRP proxy list, shared by both auto_sync_tunnel_origins (needs each
# proxy's full conf to create/match origins) and get_live_online_proxy_names
# below (needs only which names are online, for the Origins page's live-
# connectivity badge). 2026-09-20 perf fix: these used to each poll the FRP
# dashboard separately -- every GET /api/origins therefore made two
# sequential, uncached HTTP calls to the same endpoint for the same data.
# One cache entry for the whole process, not per-user -- the FRP proxy list
# isn't scoped to a tenant. 60s, not the 3s used for the tunnel list itself
# (api/tunnels.py's _TUNNELS_CACHE): this is a background truthfulness check
# shown on every page load, not something a user is actively waiting on, so
# it can afford to be slower in exchange for not hammering the FRP
# dashboard on every request. A caller that needs the truth right now (the
# Origins page "Refresh" button) passes force=True to bypass it.
_LIVE_PROXIES_CACHE: Optional[Tuple[float, List[Dict]]] = None
LIVE_STATUS_CACHE_TTL = 60.0

# origins_table.scan() measured at ~240-255ms against the real table
# (DynamoDB is cross-region from where this backend runs). Before this fix,
# a single GET /api/origins request scanned this table TWICE -- once inside
# auto_sync_tunnel_origins (global dedup check: "does some tunnel's origin
# already exist under any user?") and again inside get_origins_visible_to_user
# (shared-viewer check), back to back, same data, same request. 2026-09-20
# perf fix: one process-wide cache, short TTL so a just-created/deleted
# origin still shows up almost immediately -- explicitly invalidated below
# on every write (create/update/delete/restore) rather than relying on TTL
# alone for that case.
_ORIGINS_SCAN_CACHE: Optional[Tuple[float, List[Dict]]] = None
ORIGINS_SCAN_CACHE_TTL = 3.0

# get_origins_for_user() (db.get_origins_by_user -- a Query against the
# admin_user_id-index GSI) had NO caching at all until this fix, unlike the
# scan above -- measured at the same ~240-255ms cross-region cost per call.
# GET /api/origins calls this at least once every request via
# get_origins_visible_to_user() below; on a repeated poll (the dominant
# real traffic pattern -- the frontend refetches this endpoint
# periodically) that was 240ms paid fresh every single time even though
# the answer rarely changes within a few seconds. Keyed per-user, unlike
# the origins-table scan, because this call is already scoped to one
# user's data -- no cross-tenant leak risk from caching it this way.
_USER_ORIGINS_CACHE: Dict[str, Tuple[float, List[Dict]]] = {}
USER_ORIGINS_CACHE_TTL = 3.0


def _scan_all_origins() -> List[Dict]:
    """Raises on a genuine scan failure (with no stale cache to fall back
    on) rather than swallowing to [] -- callers have different fail-open vs
    fail-closed needs (see auto_sync_tunnel_origins) and must decide that
    for themselves, same as before this cache existed."""
    global _ORIGINS_SCAN_CACHE
    now = time.time()
    if _ORIGINS_SCAN_CACHE is not None:
        cached_time, cached_items = _ORIGINS_SCAN_CACHE
        if now - cached_time < ORIGINS_SCAN_CACHE_TTL:
            return cached_items
    try:
        items = db.origins_table.scan().get("Items", [])
    except Exception:
        if _ORIGINS_SCAN_CACHE is not None:
            return _ORIGINS_SCAN_CACHE[1]
        raise
    _ORIGINS_SCAN_CACHE = (now, items)
    return items


def _invalidate_origins_caches() -> None:
    global _ORIGINS_SCAN_CACHE
    _ORIGINS_SCAN_CACHE = None
    _USER_ORIGINS_CACHE.clear()


async def get_live_proxies(force: bool = False) -> List[Dict]:
    global _LIVE_PROXIES_CACHE
    now = time.time()
    if not force and _LIVE_PROXIES_CACHE is not None:
        cached_time, cached_proxies = _LIVE_PROXIES_CACHE
        if now - cached_time < LIVE_STATUS_CACHE_TTL:
            return cached_proxies

    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            res = await client.get(FRP_DASHBOARD_URL, auth=(FRP_ADMIN_USER, FRP_ADMIN_PASS))
            if res.status_code != 200:
                return _LIVE_PROXIES_CACHE[1] if _LIVE_PROXIES_CACHE else []
            proxies = res.json().get("proxies", [])
    except Exception as e:
        logger.warning(f"FRP daemon unreachable during live proxy poll: {e}")
        # Stale cache beats treating a flaky poll as "nothing is online".
        return _LIVE_PROXIES_CACHE[1] if _LIVE_PROXIES_CACHE else []

    _LIVE_PROXIES_CACHE = (now, proxies)
    return proxies


async def get_live_online_proxy_names(force: bool = False) -> Set[str]:
    proxies = await get_live_proxies(force=force)
    return {p.get("name") for p in proxies if p.get("status") == "online" and p.get("name")}


def validate_ip(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    ip_str = ip.strip()
    if ip_str.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ipv4_pattern.match(ip_str):
        parts = ip_str.split('.')
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return bool(domain_pattern.match(ip_str))


def create_origin(admin_user_id: str, label: str, ip: str, port: int) -> dict:
    if not validate_ip(ip):
        raise ValueError("Invalid IP address or domain format")
    
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number")
        
    # Check quota limit
    existing_origins = [o for o in get_origins_for_user(admin_user_id) if o.get("status") != "archived"]
    if len(existing_origins) >= ORIGINS_QUOTA_DEFAULT:
        raise ValueError(f"Origin quota exceeded. Maximum allowed: {ORIGINS_QUOTA_DEFAULT} active origins per account.")
        
    origin_id = str(uuid.uuid4())
    now = datetime.now().isoformat() + "Z"
    
    origin_data = {
        "id": origin_id,
        "admin_user_id": admin_user_id,
        "label": label,
        "ip": ip,
        "port": port,
        "status": "pending",
        "created_at": now,
        "updated_at": now
    }
    
    success = db.create_origin(origin_data)
    if not success:
        raise Exception("Failed to save origin to DynamoDB")

    invalidate_tenant_cache(admin_user_id)
    _invalidate_origins_caches()
    return origin_data


def get_origins_for_user(admin_user_id: str) -> list:
    now = time.time()
    cached = _USER_ORIGINS_CACHE.get(admin_user_id)
    if cached is not None and now - cached[0] < USER_ORIGINS_CACHE_TTL:
        return cached[1]
    items = db.get_origins_by_user(admin_user_id)
    _USER_ORIGINS_CACHE[admin_user_id] = (now, items)
    return items


def get_origins_visible_to_user(user_id: str) -> list:
    """Owned origins UNION origins this user was explicitly granted viewer
    access to. Use this (not get_origins_for_user) anywhere "can this user
    see it" is the question -- get_origins_for_user stays for the narrower
    "does this user own it" cases (quota, create-time dedup)."""
    owned = get_origins_for_user(user_id)
    owned_ids = {o.get("id") for o in owned}
    try:
        all_origins = _scan_all_origins()
    except Exception:
        return owned
    shared = [
        o for o in all_origins
        if o.get("id") not in owned_ids and user_id in (o.get("viewer_user_ids") or set())
    ]
    return owned + shared


def list_origin_viewers(origin_id: str) -> list:
    origin = db.get_origin_by_id(origin_id)
    if not origin:
        return []
    viewer_ids = origin.get("viewer_user_ids") or set()
    viewers = []
    for uid in viewer_ids:
        u = auth_service.get_user_by_id(uid)
        if u:
            viewers.append({
                "user_id": uid,
                "username": u.get("username", ""),
                "email": u.get("email", ""),
            })
    return viewers


def get_origin(origin_id: str) -> dict:
    return db.get_origin_by_id(origin_id)


def update_origin(origin_id: str, label: str = None, ip: str = None, port: int = None) -> bool:
    update_data = {"updated_at": datetime.now().isoformat() + "Z"}
    if label:
        update_data["label"] = label
    if ip:
        if not validate_ip(ip):
            raise ValueError("Invalid IP address or domain format")
        update_data["ip"] = ip
    if port is not None:
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port number")
        update_data["port"] = port
        
    success = db.update_origin(origin_id, update_data)
    if success:
        invalidate_tenant_cache()
        _invalidate_origins_caches()
    return success


def delete_origin(origin_id: str) -> bool:
    success = db.delete_origin(origin_id)
    if success:
        invalidate_tenant_cache()
        _invalidate_origins_caches()
    return success


def restore_origin(origin_id: str) -> bool:
    success = db.restore_origin(origin_id)
    if success:
        invalidate_tenant_cache()
        _invalidate_origins_caches()
    return success


def get_quota_info(admin_user_id: str) -> dict:
    """Return current usage vs quota limits for this user."""
    origins = get_origins_for_user(admin_user_id)
    used_origins = len([o for o in origins if o.get("status") != "archived"])
    return {
        "origins": {
            "used": used_origins,
            "max": ORIGINS_QUOTA_DEFAULT,
            "available": max(0, ORIGINS_QUOTA_DEFAULT - used_origins),
            "at_limit": used_origins >= ORIGINS_QUOTA_DEFAULT,
        },
        "domains_per_origin": {
            "max": DOMAINS_QUOTA_PER_ORIGIN,
        },
    }


async def auto_sync_tunnel_origins(user_id: str, user_role: str = "user") -> List[Dict]:
    """
    Query FRP live proxies and auto-create Origin + Domain in DynamoDB for any online tunnel
    that is not yet registered.
    """
    if not user_id:
        return []

    # 2026-09-20 perf fix: this used to poll the FRP dashboard itself,
    # separately from get_live_proxies() below (called later in this same
    # request, via api/origins.py's _attach_live_status) -- every
    # GET /api/origins therefore made the same external HTTP call twice.
    # Shares the same 60s cache now; a stale-by-up-to-60s view of "which
    # tunnels exist" is an acceptable trade for not doubling this endpoint's
    # external calls on every page load.
    proxies = await get_live_proxies()
    if not proxies:
        return []

    try:
        all_domains_items = db.domains_table.scan().get("Items", [])
    except Exception:
        all_domains_items = []
    try:
        # 2026-09-20 perf fix: shares the same short-TTL cache as
        # get_origins_visible_to_user, collapsing what used to be two
        # separate origins_table.scan() calls within the same
        # GET /api/origins request (this function runs first, so its scan
        # populates the cache the other call then reuses for free).
        all_origins_global = _scan_all_origins()
    except Exception:
        # Fail closed on this specific check: if we can't verify global
        # ownership, do not auto-create anything this cycle rather than
        # risk claiming a tunnel someone else already owns.
        return []

    created_origins = []
    need_cache_invalidation = False
    owners_to_invalidate = set()

    for p in proxies:
        status_val = p.get("status", "offline")
        if status_val != "online":
            continue

        conf = p.get("conf") or {}
        raw_name = p.get("name", "")
        custom_domains = conf.get("customDomains") or conf.get("custom_domains") or []
        domain_val = str(custom_domains[0] if custom_domains else raw_name).strip().lower()
        if not domain_val:
            continue

        local_ip = conf.get("localIP") or conf.get("local_ip") or "127.0.0.1"
        # frps' dashboard API never carries localPort (confirmed live against
        # a real proxy, 2026-09-19) -- the port the tunnel config generator
        # embeds in metadatas.port is the only reliable source; the
        # localPort/local_port reads stay only for pre-fix tunnel configs.
        local_port = (
            (conf.get("metadatas") or {}).get("port")
            or conf.get("localPort") or conf.get("local_port") or 80
        )

        # 2026-09-19 fix: ownership used to default to `user_id` -- whoever
        # is CALLING this function (i.e. whoever has the Tunnels/Origins page
        # open right now), a first-viewer race, not real RBAC. The FRP
        # webhook gatekeeper (api/tunnels.py, NewProxy) already verifies each
        # proxy's domain-scoped JWT and is the only place that authoritatively
        # knows who minted it; it records that into _PROXY_OWNERS. Deferred
        # import: origin_service is imported by api.tunnels itself, so a
        # module-level import here would be circular.
        from api.tunnels import get_proxy_owner
        true_owner_id = get_proxy_owner(raw_name)
        if not true_owner_id:
            # NewProxy hasn't fired since this process started (e.g. a proxy
            # that was already connected before a backend restart) -- do not
            # fall back to the caller's id, that is exactly the bug being
            # fixed. It will be picked up correctly on the tunnel's next
            # reconnect, which re-fires NewProxy.
            logger.warning(f"Skipping auto-create for tunnel '{raw_name}': true owner not yet known (awaiting next reconnect)")
            continue

        # Check if already exists -- scanned GLOBALLY, not scoped to the
        # calling user. A dedup check scoped to the caller's own origins
        # (the previous shape of this check) only prevents a user from
        # duplicating their OWN origin; it does nothing when the viewer is
        # someone other than true_owner_id, which is routine now that
        # ownership no longer depends on who's looking -- that produced
        # duplicate origin rows every time a non-owner viewed the page.
        matched_origin = None
        for o in all_origins_global:
            o_lbl = str(o.get("label", "")).lower()
            o_ip = str(o.get("ip", "")).lower()
            o_tunnel = str(o.get("tunnel_name", "")).lower()

            if (domain_val in o_lbl or domain_val in o_ip or domain_val == o_ip or
                raw_name.lower() in o_tunnel or raw_name.lower() in o_lbl or
                raw_name.lower() in o_ip):
                matched_origin = o
                break

        if matched_origin:
            existing_owner = matched_origin.get("admin_user_id")
            if existing_owner != true_owner_id:
                # Should not normally happen -- token minting is checked
                # against domain ownership at issue time -- but if a domain
                # changed hands after a token was minted, don't silently
                # reassign it here; that decision needs a human.
                logger.warning(f"Tunnel '{raw_name}' has origin owned by {existing_owner} but its JWT says {true_owner_id}; leaving ownership unchanged")
                continue
            if matched_origin.get("status") == "archived":
                db.update_origin(matched_origin.get("id"), {"status": "active", "updated_at": datetime.now().isoformat() + "Z"})
                need_cache_invalidation = True
                owners_to_invalidate.add(true_owner_id)
            continue

        # Create new origin for this tunnel
        origin_id = str(uuid.uuid4())
        now = datetime.now().isoformat() + "Z"
        clean_label = f"Tunnel ({domain_val})"

        origin_data = {
            "id": origin_id,
            "admin_user_id": true_owner_id,
            "label": clean_label,
            "ip": domain_val if "." in domain_val else local_ip,
            "port": int(local_port) if isinstance(local_port, (int, str)) and str(local_port).isdigit() else 80,
            "status": "active",
            "is_tunnel": True,
            "tunnel_name": raw_name,
            "created_at": now,
            "updated_at": now,
        }

        success = db.create_origin(origin_data)
        if success:
            created_origins.append(origin_data)
            # Feed the matched_origin de-dup check above for any later proxy
            # in this same pass, so two proxies for the same domain in one
            # FRP poll can't both create an origin.
            all_origins_global.append(origin_data)
            need_cache_invalidation = True
            owners_to_invalidate.add(true_owner_id)
            logger.info(f"Auto-created Origin {clean_label} (ID: {origin_id}) for active tunnel")

            # Also ensure domain exists in waf_domains
            if "." in domain_val and not any(str(d.get("domain_name", "")).lower() == domain_val for d in all_domains_items):
                domain_id = str(uuid.uuid4())
                domain_data = {
                    "id": domain_id,
                    "origin_id": origin_id,
                    "domain_name": domain_val,
                    "verification_token": f"waf-tunnel-{uuid.uuid4().hex[:12]}",
                    "dns_verified": True,
                    "ssl_status": "active",
                    "created_at": now,
                    "updated_at": now,
                }
                try:
                    db.domains_table.put_item(Item=domain_data)
                    all_domains_items.append(domain_data)
                    logger.info(f"Auto-created Domain {domain_val} (ID: {domain_id}) for origin {origin_id}")
                except Exception as ex:
                    logger.error(f"Failed to auto-create domain {domain_val}: {ex}")

    if need_cache_invalidation:
        for uid in (owners_to_invalidate or {user_id}):
            invalidate_tenant_cache(uid)
        _invalidate_origins_caches()

    return created_origins
