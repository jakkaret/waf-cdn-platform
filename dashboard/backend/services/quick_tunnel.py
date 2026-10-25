"""Quick tunnels: a public address for a site running on a private machine,
for a user who has no domain of their own (the trycloudflare.com idea).

The platform names the host -- t-<8 random characters>.<QUICK_TUNNEL_ZONE> --
and the user never chooses it. That keeps F-129 closed: there is no name to
squat and no way to pick one that looks like someone else's site. Creating a
quick tunnel writes, in one transaction, an agent-mode origin, its domain row
already DNS-verified (the zone's wildcard record points at the edge, so there
is nothing for the user to prove) and a waf.quick_tunnels row (migration
0016). From there the existing paths take over unchanged:
/api/tunnels/config-generator mints the tunnel token because the user owns a
verified domain, the frps gatekeeper binds the proxy, and check-ssl-allowed
lets the edge issue the certificate.

The zone is a different registrable domain from the dashboard on purpose: a
page served through a quick tunnel can set cookies for its parent domain, and
must not be able to set them for the dashboard.

Limits: QUICK_TUNNELS_PER_USER at a time; a creation rate per user and in
total (each new host can cost a Let's Encrypt certificate, and every host in
the zone shares one weekly quota); a quick tunnel whose agent stays offline
for QUICK_TUNNEL_IDLE_DAYS is removed by quick_tunnel_expiry_worker.
"""
import asyncio
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from db import pool
from services import audit_log
from services.dynamodb_service import DuplicateDomain, DynamoDBService
from services.tenant_service import invalidate_tenant_cache
from services.txn import atomic
import services.origin_service as origin_service

logger = logging.getLogger(__name__)
db = DynamoDBService()

ZONE = os.getenv("WAF_QUICK_TUNNEL_ZONE", "tunnel.originweb.site").strip().lower().strip(".")
PER_USER = int(os.getenv("QUICK_TUNNELS_PER_USER", "3"))
IDLE_DAYS = int(os.getenv("QUICK_TUNNEL_IDLE_DAYS", "7"))
CREATES_PER_USER_PER_DAY = int(os.getenv("QUICK_TUNNEL_CREATES_PER_USER_PER_DAY", "5"))
CREATES_PER_WEEK = int(os.getenv("QUICK_TUNNEL_CREATES_PER_WEEK", "30"))
EXPIRY_CHECK_SECONDS = 600

# No 0/o or 1/l/i: the name is read off a screen and typed into a browser.
_LABEL_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_LABEL_LENGTH = 8
_NAME_ATTEMPTS = 5

_limiter = None


class QuickTunnelError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def in_zone(host: str) -> bool:
    """The zone apex or any host under it."""
    h = str(host or "").strip().lower().rstrip(".")
    return bool(ZONE) and (h == ZONE or h.endswith("." + ZONE))


def new_hostname() -> str:
    label = "".join(secrets.choice(_LABEL_ALPHABET) for _ in range(_LABEL_LENGTH))
    return f"t-{label}.{ZONE}"


def count_active(user_id: str) -> int:
    row = pool.q1(
        "SELECT count(*) AS n FROM quick_tunnels q JOIN origins o ON o.id = q.origin_id "
        "WHERE q.user_id = %s::uuid AND o.status NOT IN ('archived', 'deleted')", (user_id,))
    return int(row["n"]) if row else 0


def _check_create_rate(user_id: str) -> None:
    """Fail closed: if the limiter is down, nobody creates one."""
    global _limiter
    if _limiter is None:
        from services.rate_limiter import RedisRateLimiter
        _limiter = RedisRateLimiter()
    allowed, _, retry_after = _limiter.is_allowed(
        f"quick-tunnel-create:{user_id}", CREATES_PER_USER_PER_DAY, 86400, fail_open=False)
    if not allowed:
        raise QuickTunnelError(429, f"You can create {CREATES_PER_USER_PER_DAY} quick tunnels a day. "
                                    f"Try again in {max(1, retry_after // 3600)} hour(s).")
    allowed, _, _ = _limiter.is_allowed("quick-tunnel-create:all", CREATES_PER_WEEK, 7 * 86400, fail_open=False)
    if not allowed:
        raise QuickTunnelError(429, "The platform has handed out its quick tunnels for this week. "
                                    "Try again later, or connect a domain of your own.")


def _name_taken(host: str) -> bool:
    if db.get_verified_domain(host) is not None or db.tunnel_domain_origin(host):
        return True
    return pool.q1("SELECT 1 AS x FROM domains WHERE domain_name = %s", (host,)) is not None


def create(current_user: Dict[str, Any], port: int) -> Dict[str, Any]:
    """Create one quick tunnel for `current_user`; the caller then runs the
    post-verify steps (api.domains.after_domain_verified)."""
    user_id = str(current_user.get("user_id") or "")
    if not ZONE:
        raise QuickTunnelError(503, "Quick tunnels are not set up on this server.")
    if not (1 <= int(port) <= 65535):
        raise QuickTunnelError(422, "port must be between 1 and 65535")
    if count_active(user_id) >= PER_USER:
        raise QuickTunnelError(400, f"You already have {PER_USER} quick tunnels. Remove one before creating another.")
    if origin_service.get_quota_info(user_id)["origins"]["at_limit"]:
        raise QuickTunnelError(400, f"Origin quota exceeded. Maximum allowed: "
                                    f"{origin_service.ORIGINS_QUOTA_DEFAULT} active origins per account.")
    _check_create_rate(user_id)

    for _ in range(_NAME_ATTEMPTS):
        host = new_hostname()
        if _name_taken(host):
            continue
        try:
            return _create_records(current_user, host, int(port))
        except DuplicateDomain:
            continue
    raise QuickTunnelError(503, "Could not find a free name. Try again.")


def _create_records(current_user: Dict[str, Any], host: str, port: int) -> Dict[str, Any]:
    user_id = str(current_user.get("user_id"))
    origin_id = str(uuid.uuid4())
    now = datetime.now().isoformat() + "Z"
    origin = {
        "id": origin_id, "admin_user_id": user_id, "label": host, "ip": host, "port": port,
        "status": "pending", "connection_mode": "agent", "origin_scheme": "http",
        "created_at": now, "updated_at": now,
    }
    domain = {
        "id": str(uuid.uuid4()), "origin_id": origin_id, "domain_name": host,
        "verification_token": f"waf-quick-{uuid.uuid4().hex[:12]}",
        "dns_verified": True, "ssl_status": "pending", "created_at": now, "updated_at": now,
    }
    with atomic():
        if not db.create_origin(origin):
            raise QuickTunnelError(400, "The account for this request no longer exists.")
        db.create_domain(domain)
        pool.exec_("INSERT INTO quick_tunnels (origin_id, user_id, domain_name) VALUES (%s::uuid, %s::uuid, %s)",
                   (origin_id, user_id, host))
        audit_log.write_audit_event(
            scope_id=origin_id,
            actor_user_id=user_id,
            actor_username=current_user.get("username", ""),
            action="quick_tunnel.create",
            summary=f"สร้าง quick tunnel: {host}",
            details={"domain_name": host, "port": port},
        )
    invalidate_tenant_cache(user_id)
    origin_service._invalidate_origins_caches()
    logger.info("quick tunnel %s created for user %s", host, user_id)
    return {"origin_id": origin_id, "domain_name": host, "port": port}


def _row(r: Dict[str, Any], online: Iterable[str] = ()) -> Dict[str, Any]:
    is_online = r["domain_name"] in set(online)
    seen = r["last_seen_at"] or r["created_at"]
    return {
        "origin_id": str(r["origin_id"]),
        "domain_name": r["domain_name"],
        "url": f"https://{r['domain_name']}",
        "port": r["port"],
        "owner_id": str(r["user_id"]),
        "owner_username": r["username"],
        "created_at": r["created_at"].isoformat(),
        "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
        "is_online": is_online,
        # While the agent is connected nothing expires.
        "expires_at": None if is_online else (seen + timedelta(days=IDLE_DAYS)).isoformat(),
    }


_LIST_SQL = (
    "SELECT q.origin_id, q.user_id, q.domain_name, q.created_at, q.last_seen_at, o.port, u.username "
    "FROM quick_tunnels q JOIN origins o ON o.id = q.origin_id JOIN users u ON u.user_id = q.user_id "
    "WHERE o.status NOT IN ('archived', 'deleted')"
)


def list_tunnels(user_id: Optional[str] = None, online: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """One user's quick tunnels, or every user's when user_id is None."""
    online = set(online)
    if user_id is None:
        rows = pool.q(_LIST_SQL + " ORDER BY q.created_at DESC")
    else:
        rows = pool.q(_LIST_SQL + " AND q.user_id = %s::uuid ORDER BY q.created_at DESC", (user_id,))
    return [_row(r, online) for r in rows]


def get(origin_id: str) -> Optional[Dict[str, Any]]:
    try:
        uuid.UUID(str(origin_id))
    except ValueError:
        return None
    r = pool.q1(_LIST_SQL + " AND q.origin_id = %s::uuid", (origin_id,))
    return _row(r) if r else None


def remove(origin_id: str, actor: Optional[Dict[str, Any]], reason: str) -> Optional[Dict[str, Any]]:
    """Delete a quick tunnel for good: its origin (cascading to the domain row
    and the quick_tunnels row) and the proxy name the gatekeeper recorded. The
    name is never reused (it is random), so nothing is kept to reserve it.
    The audit event is global: the origin it would belong to is gone."""
    tunnel = get(origin_id)
    if not tunnel:
        return None
    with atomic():
        pool.exec_("DELETE FROM tunnel_proxy_owners WHERE domain_name = %s", (tunnel["domain_name"],))
        audit_log.write_audit_event(
            scope_id="global",
            actor_user_id=str((actor or {}).get("user_id") or ""),
            actor_username=(actor or {}).get("username") or "system",
            action="quick_tunnel.remove",
            summary=f"ลบ quick tunnel: {tunnel['domain_name']} ({reason})",
            details={"origin_id": tunnel["origin_id"], "domain_name": tunnel["domain_name"],
                     "owner_user_id": tunnel["owner_id"], "owner_username": tunnel["owner_username"],
                     "reason": reason},
        )
        db.hard_delete_origin(origin_id)
    invalidate_tenant_cache(tunnel["owner_id"])
    origin_service._invalidate_origins_caches()
    logger.info("quick tunnel %s removed (%s)", tunnel["domain_name"], reason)
    return tunnel


def online_hosts(proxies: Iterable[Dict[str, Any]]) -> set:
    """Hosts in the zone with a live proxy on frps."""
    hosts = set()
    for p in proxies:
        if p.get("status") != "online":
            continue
        conf = p.get("conf") or {}
        for d in (conf.get("customDomains") or conf.get("custom_domains") or []):
            d = str(d or "").strip().lower().rstrip(".")
            if in_zone(d):
                hosts.add(d)
    return hosts


def expire_idle(online: Iterable[str]) -> List[str]:
    """Mark the online ones seen now; remove those offline for IDLE_DAYS.
    Returns the removed hosts."""
    online = sorted(set(online))
    if online:
        pool.exec_("UPDATE quick_tunnels SET last_seen_at = now() WHERE domain_name = ANY(%s)", (online,))
    due = pool.q(
        "SELECT origin_id, domain_name FROM quick_tunnels "
        "WHERE COALESCE(last_seen_at, created_at) < now() - make_interval(days => %s)", (IDLE_DAYS,))
    removed = []
    for r in due:
        if r["domain_name"] in online:
            continue
        if remove(str(r["origin_id"]), None, f"offline for {IDLE_DAYS} days"):
            removed.append(r["domain_name"])
    return removed


async def quick_tunnel_expiry_worker():
    while True:
        await asyncio.sleep(EXPIRY_CHECK_SECONDS)
        try:
            proxies = await origin_service.get_live_proxies(force=True)
            if not proxies:
                # frps unreachable or its credentials unset look the same as
                # "nothing online": never remove anything on that answer.
                continue
            removed = await asyncio.to_thread(expire_idle, online_hosts(proxies))
            if removed:
                logger.info("quick tunnels expired: %s", ", ".join(removed))
        except Exception as exc:
            logger.warning("quick tunnel expiry check failed: %s", exc)
