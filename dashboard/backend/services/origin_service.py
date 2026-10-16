import asyncio
import uuid
import re
import os
import time
import ipaddress
import httpx
import logging
from typing import List, Dict, Optional, Any, Set, Tuple
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.dns_service import is_claimable_own_wildcard_subdomain, verify_domain_dns
from services.hostnames import canonical_or_none
from services.tenant_service import invalidate_tenant_cache
from services.auth_service import AuthService

logger = logging.getLogger(__name__)
db = DynamoDBService()
auth_service = AuthService()

# Configurable quota — set ORIGINS_QUOTA_DEFAULT in .env to override
ORIGINS_QUOTA_DEFAULT = int(os.getenv("ORIGINS_QUOTA_DEFAULT", "10"))
DOMAINS_QUOTA_PER_ORIGIN = int(os.getenv("DOMAINS_QUOTA_PER_ORIGIN", "10"))

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")


def frp_admin_auth():
    """(user, password) for the frps dashboard API, or None when either is
    unset. There is deliberately no fallback: the old hard-coded admin
    password was public, so without configured credentials the frps API is
    simply not called (H70/H87)."""
    user = os.getenv("FRP_ADMIN_USER", "")
    password = os.getenv("FRP_ADMIN_PASS", "")
    if not user or not password:
        return None
    return (user, password)


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

# A full origins scan measured at ~240-255ms against the real table
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
        items = db.list_origins()
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

    auth = frp_admin_auth()
    if auth is None:
        logger.warning("FRP_ADMIN_USER/FRP_ADMIN_PASS not set; skipping the frps proxy poll")
        return _LIVE_PROXIES_CACHE[1] if _LIVE_PROXIES_CACHE else []
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            res = await client.get(FRP_DASHBOARD_URL, auth=auth)
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


# Literal IPs an origin address may point at even though they are otherwise
# non-public. Comma-separated CIDRs in ORIGIN_ALLOW_PRIVATE_CIDRS; defaults to
# the QA echo container on waf-net so the integration suite can register it.
_ALLOWED_PRIVATE_NETS = []
for _c in os.getenv("ORIGIN_ALLOW_PRIVATE_CIDRS", "172.18.0.250/32").split(","):
    _c = _c.strip()
    if not _c:
        continue
    try:
        _ALLOWED_PRIVATE_NETS.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        logger.warning("Ignoring invalid CIDR in ORIGIN_ALLOW_PRIVATE_CIDRS: %r", _c)

# RFC 5737 documentation ranges: globally non-routable but NOT internal, so they
# raise no SSRF concern as an origin address -- and they are the repo's
# test-fixture convention for a "safe fake public IP". Always allowed.
_SAFE_NONINTERNAL_NETS = [
    ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


def validate_ip(ip: str) -> bool:
    """Validate an origin address (literal IP or hostname).

    Literal IPs must be public routable addresses. Loopback, private, link-
    local, multicast, reserved and unspecified ranges are rejected unless
    explicitly allowlisted via ORIGIN_ALLOW_PRIVATE_CIDRS -- otherwise an
    origin address could point the WAF's own upstream at internal services
    (SSRF). Hostnames are still accepted (tunnel/DNS origins resolve later);
    the bare label "localhost" is not.
    """
    if not ip or not isinstance(ip, str):
        return False
    ip_str = ip.strip()
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        addr = None
    if addr is not None:
        if any(addr in net for net in _ALLOWED_PRIVATE_NETS):
            return True
        if any(addr in net for net in _SAFE_NONINTERNAL_NETS):
            return True
        return not (
            addr.is_loopback or addr.is_private or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        )
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    if not domain_pattern.match(ip_str):
        return False
    # P3.8 (H38): a name is held to the same rule as a literal -- one that is
    # internal by convention, or resolves to an internal address now, is
    # refused (unless that address is allowlisted). A name that does not
    # resolve yet (a tunnel host before its DNS exists) is accepted.
    host = ip_str.lower().rstrip(".")
    if host.endswith(_INTERNAL_NAME_SUFFIXES):
        return False
    for resolved in _resolve_addresses(host):
        if not validate_ip(resolved):
            return False
    return True


_INTERNAL_NAME_SUFFIXES = (".internal", ".local", ".localhost", ".lan", ".home.arpa", ".localdomain")


def _resolve_addresses(host: str) -> List[str]:
    import socket
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return []
    return sorted({info[4][0].split("%", 1)[0] for info in infos})


CONNECTION_MODES = ("direct", "agent")
ORIGIN_SCHEMES = ("http", "https")


def create_origin(admin_user_id: str, label: str, ip: str, port: int,
                  connection_mode: Optional[str] = None, origin_scheme: Optional[str] = None) -> dict:
    """connection_mode / origin_scheme are set only by the connect flow
    (api/onboarding.py). Leaving them out keeps the old record shape, so an
    origin made through POST /api/origins behaves exactly as before."""
    if not validate_ip(ip):
        raise ValueError("Invalid IP address or domain format")

    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number")
    if connection_mode is not None and connection_mode not in CONNECTION_MODES:
        raise ValueError("Invalid connection mode")
    if origin_scheme is not None and origin_scheme not in ORIGIN_SCHEMES:
        raise ValueError("Invalid origin scheme")
        
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
    if connection_mode is not None:
        origin_data["connection_mode"] = connection_mode
    if origin_scheme is not None:
        origin_data["origin_scheme"] = origin_scheme

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
    OR editor access to (Team Workspace, 2026-09-22 -- an editor must see
    the origin they were granted write access to, the same reasoning
    services/rbac.py's verify_origin_access already applies per-request).
    Use this (not get_origins_for_user) anywhere "can this user see it" is
    the question -- get_origins_for_user stays for the narrower "does this
    user own it" cases (quota, create-time dedup)."""
    owned = get_origins_for_user(user_id)
    owned_ids = {o.get("id") for o in owned}
    try:
        shared = db.get_origins_shared_with(user_id)
    except Exception:
        return owned
    return owned + [o for o in shared if o.get("id") not in owned_ids]


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


def list_origin_editors(origin_id: str) -> list:
    """Team Workspace (2026-09-22): mirrors list_origin_viewers exactly for
    editor_user_ids."""
    origin = db.get_origin_by_id(origin_id)
    if not origin:
        return []
    editor_ids = origin.get("editor_user_ids") or set()
    editors = []
    for uid in editor_ids:
        u = auth_service.get_user_by_id(uid)
        if u:
            editors.append({
                "user_id": uid,
                "username": u.get("username", ""),
                "email": u.get("email", ""),
            })
    return editors


def get_origin(origin_id: str) -> dict:
    return db.get_origin_by_id(origin_id)


def update_origin(origin_id: str, label: str = None, ip: str = None, port: int = None,
                   tech_stack_tags: List[str] = None) -> bool:
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
    if tech_stack_tags is not None:
        update_data["tech_stack_tags"] = tech_stack_tags

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


def discard_new_origin(origin_id: str, admin_user_id: str) -> None:
    """Hard-delete an origin that a multi-step flow created moments ago and
    then could not finish (api/onboarding.py /connect). Not an archive: the
    row never held anything the user saw."""
    db.hard_delete_origin(origin_id)
    invalidate_tenant_cache(admin_user_id)
    _invalidate_origins_caches()
    from services import shield_sync
    shield_sync.reconcile_quietly(db)


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
        all_domains_items = db.list_domains()
    except Exception:
        all_domains_items = []
    try:
        # 2026-09-20 perf fix: shares the same short-TTL cache as
        # get_origins_visible_to_user, collapsing what used to be two
        # separate full origins scans within the same
        # GET /api/origins request (this function runs first, so its scan
        # populates the cache the other call then reuses for free).
        # A copy: new origins are appended below for de-duplication, and the
        # scan result is a cache shared by the whole process (P3.7).
        all_origins_global = [dict(o) for o in _scan_all_origins()]
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
        # P3.3: one canonical spelling; a proxy without a valid host is skipped.
        domain_val = canonical_or_none(custom_domains[0] if custom_domains else "")
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

        # The owner is the account whose tunnel token opened this proxy,
        # recorded by the NewProxy hook (api/tunnels.py, PostgreSQL since
        # P3.1) -- never whoever is viewing the page. Deferred import:
        # origin_service is imported by api.tunnels itself.
        from api.tunnels import get_proxy_owner
        true_owner_id = get_proxy_owner(raw_name)
        if not true_owner_id:
            logger.warning(f"Skipping auto-create for tunnel '{raw_name}': owner not recorded (awaiting next reconnect)")
            continue

        # P3.7 (C5/C6): exact matches only, scanned globally -- the origin
        # this proxy already runs as (tunnel_name), the origin that verified
        # this host, or the connect flow's agent origin that stores the host
        # as its address. Substring matching on labels let one tenant's
        # proxy land on (or skip) another tenant's origin.
        verified = db.get_verified_domain(domain_val)
        matched_origin = None
        for o in all_origins_global:
            if (str(o.get("tunnel_name") or "") == raw_name
                    or (verified and str(o.get("id")) == verified.get("origin_id"))
                    or str(o.get("ip") or "").strip().lower() == domain_val):
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
            if matched_origin.get("status") in ("archived", "deleted"):
                # P3.6 (H32): an origin its owner archived stays archived
                # while its tunnel is still online; it is restored on purpose.
                continue
            if matched_origin.get("connection_mode") == "agent" and (
                matched_origin.get("status") == "pending" or not matched_origin.get("is_tunnel")
            ):
                # An origin made by the connect flow for an agent stores the
                # domain as its address, which is what matched here. Its agent
                # is now online: mark it as the tunnel origin instead of
                # leaving it pending next to an auto-created duplicate.
                update = {
                    "status": "active",
                    "is_tunnel": True,
                    "tunnel_name": raw_name,
                    "updated_at": datetime.now().isoformat() + "Z",
                }
                db.update_origin(matched_origin.get("id"), update)
                matched_origin.update(update)
                need_cache_invalidation = True
                owners_to_invalidate.add(true_owner_id)
            continue

        # P3.6 (H74): a new origin counts against the owner's quota.
        if get_quota_info(true_owner_id)["origins"]["at_limit"]:
            logger.warning(f"Skipping auto-create for tunnel '{raw_name}': owner {true_owner_id} is at the origin quota")
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
                token = f"waf-tunnel-{uuid.uuid4().hex[:12]}"
                # A tunnel token only proves the domain is not someone else's
                # *in this system*, not that the caller owns it. Verify only a
                # subdomain of our own zone, or a domain whose DNS already
                # points at us; otherwise it stays pending and
                # dns_verification_worker re-checks it every minute.
                verified = is_claimable_own_wildcard_subdomain(domain_val) or await asyncio.to_thread(
                    verify_domain_dns, domain_val, token
                )
                domain_data = {
                    "id": domain_id,
                    "origin_id": origin_id,
                    "domain_name": domain_val,
                    "verification_token": token,
                    "dns_verified": verified,
                    "ssl_status": "active" if verified else "none",
                    "created_at": now,
                    "updated_at": now,
                }
                try:
                    db.create_domain(domain_data)
                    all_domains_items.append(domain_data)
                    logger.info(f"Auto-created Domain {domain_val} (ID: {domain_id}) for origin {origin_id}")
                except Exception as ex:
                    logger.error(f"Failed to auto-create domain {domain_val}: {ex}")

    if need_cache_invalidation:
        for uid in (owners_to_invalidate or {user_id}):
            invalidate_tenant_cache(uid)
        _invalidate_origins_caches()

    return created_origins
