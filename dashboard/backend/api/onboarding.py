"""Self-service onboarding: connect a site from its domain.

GET  /status            -- where the user's newest origin stands (resume info)
POST /inspect           -- read the domain's current DNS and probe the server
                           behind it, to suggest direct vs agent
POST /connect           -- create the origin and its domain in one call
GET  /progress/{id}     -- DNS / connection / HTTPS for each domain of an
                           origin, re-checked on each call (throttled)

The old wizard needed: create origin (label, IP, port) -> add domain -> set
CNAME + TXT -> press verify until DNS propagated -> generate agent command ->
press "installed" (never checked). /connect + /progress replace that with one
form and a page that checks itself; every step still goes through the same
services (origin_service.create_origin quota/validation, the domain
ownership checks, verify_domain_dns, the FRP gatekeeper for agent tokens).
"""
import asyncio
import os
import time
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from services.rbac import ARCHIVED_ORIGIN_STATUSES, get_current_user, verify_origin_access
import services.origin_service as origin_service
from services import site_connect
from services import nginx_site_service
from services.dns_service import verify_domain_dns

router = APIRouter(prefix="/api/onboarding", tags=["Onboarding"])



def compute_onboarding_status(origins: list, domain_items: list) -> dict:
    """Status of the user's NEWEST origin, not of the account as a whole.

    It used to be account-wide: one verified domain on any origin (or a
    shared origin with a live tunnel) made every later origin read "done", so
    the wizard jumped straight to its success screen before the new origin had
    a domain at all. `origins` should be the caller's own, non-archived ones.
    """
    origin_count = len(origins)
    has_origin = origin_count > 0

    domain_configured = False
    domain_verified = False
    resume_origin_id = None
    resume_domain_id = None
    resume_domain_name = None

    if origins:
        latest = max(origins, key=lambda o: o.get("created_at", ""))
        resume_origin_id = latest.get("id") or latest.get("origin_id")
        if latest.get("tunnel_domains"):
            # A tunnel_domains entry only exists once a real agent has
            # actually connected and claimed it -- that's already stronger
            # evidence of a live setup than a domains_table row alone.
            domain_configured = True
            domain_verified = True
        own = [d for d in domain_items if d.get("origin_id") == resume_origin_id]
        if own:
            domain_configured = True
            # Any verified domain completes the origin, whatever the scan order.
            domain_verified = domain_verified or any(d.get("dns_verified") for d in own)
            # Resume on a still-unverified domain if there is one.
            pick = next((d for d in own if not d.get("dns_verified")), own[0])
            resume_domain_id = pick.get("id") or pick.get("domain_id")
            resume_domain_name = pick.get("domain_name")

    if not has_origin:
        next_step = "create_origin"
    elif not domain_configured:
        next_step = "add_domain"
    elif not domain_verified:
        next_step = "verify_domain"
    else:
        next_step = "done"

    return {
        "has_origin": has_origin,
        "origin_count": origin_count,
        "domain_configured": domain_configured,
        "domain_verified": domain_verified,
        "next_step": next_step,
        "onboarding_complete": next_step == "done",
        "resume_origin_id": resume_origin_id,
        "resume_domain_id": resume_domain_id,
        "resume_domain_name": resume_domain_name,
    }


@router.get("/status")
async def get_onboarding_status(current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")

    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    origins = [
        o for o in origin_service.get_origins_for_user(user_id)
        if o.get("status") not in ARCHIVED_ORIGIN_STATUSES
    ]

    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    domain_items = db.list_domains()

    return compute_onboarding_status(origins, domain_items)


# --- connect flow ---------------------------------------------------------

INSPECT_LIMIT = 20            # per user
INSPECT_WINDOW_SECONDS = 600  # 10 minutes
_inspect_limiter = None


def _check_inspect_rate(user_id: str) -> None:
    """Each inspect makes DNS lookups and up to two outbound connections, so
    it is capped per user; if the limiter itself is down, refuse (the manual
    path still works without it)."""
    global _inspect_limiter
    if _inspect_limiter is None:
        from services.rate_limiter import RedisRateLimiter
        _inspect_limiter = RedisRateLimiter()
    allowed, _, retry_after = _inspect_limiter.is_allowed(
        f"onboarding-inspect:{user_id}", INSPECT_LIMIT, INSPECT_WINDOW_SECONDS, fail_open=False
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many domain checks. Try again in a few minutes.",
            headers={"Retry-After": str(retry_after)},
        )


def _hostname(value: str) -> str:
    from api.domains import _validate_hostname
    return _validate_hostname(value)


class InspectRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _domain_is_hostname(cls, v: str) -> str:
        return _hostname(v)


@router.post("/inspect")
async def inspect_domain(payload: InspectRequest, current_user: dict = Depends(get_current_user)):
    from api.domains import _assert_platform_subdomain_allowed, domain_registered
    _assert_platform_subdomain_allowed(payload.domain, current_user)
    if await asyncio.to_thread(domain_registered, payload.domain, current_user.get("user_id")):
        return {"domain": payload.domain, "already_registered": True}
    _check_inspect_rate(current_user.get("user_id"))
    result = await asyncio.to_thread(site_connect.inspect_domain, payload.domain)
    result["already_registered"] = False
    return result


class ConnectRequest(BaseModel):
    domain: str
    mode: Literal["direct", "agent"]
    # agent: the port the site listens on, on the machine running the agent.
    # direct: the origin's port (443/80 as found by /inspect, or typed).
    port: int = Field(ge=1, le=65535)
    origin_address: Optional[str] = None
    scheme: Optional[Literal["http", "https"]] = None

    @field_validator("domain")
    @classmethod
    def _domain_is_hostname(cls, v: str) -> str:
        return _hostname(v)


@router.post("/connect")
async def connect_site(payload: ConnectRequest, current_user: dict = Depends(get_current_user)):
    from api.domains import (
        _assert_platform_subdomain_allowed, assert_domain_available, create_domain_record,
        _mark_verified, after_domain_verified,
    )
    user_id = current_user.get("user_id")
    domain = payload.domain
    # Check everything that can fail on the domain *before* creating the
    # origin, so a refused domain never leaves an empty origin behind.
    _assert_platform_subdomain_allowed(domain, current_user)
    assert_domain_available(domain, owner_id=user_id)

    if payload.mode == "direct":
        address = (payload.origin_address or "").strip().lower()
        if not address:
            raise HTTPException(status_code=400, detail="origin_address is required for a direct connection")
        # Checked first only for a clearer message; direct_upstream_allowed
        # below refuses these addresses too (and is what reconcile enforces).
        ours = await asyncio.to_thread(site_connect.platform_ips)
        if address in ours or address in {str(ip) for ip in nginx_site_service.platform_self_ips()}:
            raise HTTPException(status_code=400, detail="That address is the WAF edge itself, not your server")
        if not nginx_site_service.direct_upstream_allowed(address):
            # IP literal only: nginx resolves a hostname at reload time, so a
            # name could later point the WAF's upstream at its own services.
            raise HTTPException(
                status_code=400,
                detail="A direct connection needs your server's public IP address (not a hostname); "
                       "use the agent for anything else",
            )
        scheme = payload.scheme or ("https" if payload.port == 443 else "http")
    else:
        # The agent carries traffic; the address is the domain, which is also
        # what auto_sync_tunnel_origins matches the live tunnel on.
        address = domain
        scheme = "http"

    try:
        origin = origin_service.create_origin(
            admin_user_id=user_id, label=domain, ip=address, port=payload.port,
            connection_mode=payload.mode, origin_scheme=scheme,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    origin_id = origin["id"]

    try:
        created = create_domain_record(origin_id, domain, current_user)
    except Exception:
        # Roll back everything this call wrote. create_domain_record can fail
        # after its put_item (audit write, config sync), and a domain row left
        # pointing at a deleted origin would block the name for good.
        from api.domains import db as domains_db
        try:
            domains_db.delete_domains_for_origin(origin_id)
        finally:
            origin_service.discard_new_origin(origin_id, user_id)
        raise

    verified = bool(created.get("auto_verified"))
    domain_row = created["domain"]
    if not verified:
        # Most customers add the record after this call, but someone moving
        # an already-pointed domain is done right here.
        if await asyncio.to_thread(verify_domain_dns, domain, domain_row["dns_verification_token"]):
            _mark_verified(domain_row["domain_id"])
            verified = True
    if verified:
        await after_domain_verified(origin_id, domain)
        domain_row = dict(domain_row, verification_status="verified")

    return {
        "origin_id": origin_id,
        "connection_mode": payload.mode,
        "domain": domain_row,
        "dns_instructions": created.get("dns_instructions") or None,
        "verified": verified,
    }


# --- progress -------------------------------------------------------------

VERIFY_THROTTLE_SECONDS = 15
FRP_FORCE_POLL_SECONDS = 15
_last_verify: dict = {}       # domain_id -> (monotonic time, current dns)
_last_frp_poll: dict = {}     # origin_id -> monotonic time
_last_reconcile_request: dict = {}


def _domains_for_origin(origin_id: str) -> list:
    from api.domains import db as domains_db
    return domains_db.list_domains(origin_id=origin_id)


async def _check_pending(d: dict) -> tuple:
    """(verified now?, current DNS) -- at most one real check per domain per
    VERIFY_THROTTLE_SECONDS however often the page polls."""
    from api.domains import _mark_verified, after_domain_verified
    domain_id = d.get("id")
    now = time.monotonic()
    last = _last_verify.get(domain_id)
    if last and now - last[0] < VERIFY_THROTTLE_SECONDS:
        return False, last[1]
    name = d.get("domain_name", "")
    ok = await asyncio.to_thread(verify_domain_dns, name, d.get("verification_token"))
    current = None if ok else await asyncio.to_thread(site_connect.current_dns, name)
    _last_verify[domain_id] = (now, current)
    if ok:
        _mark_verified(domain_id)
        await after_domain_verified(d.get("origin_id"), name)
    return ok, current


def _proxy_online_for(domain: str, proxies: list) -> bool:
    for p in proxies:
        if p.get("status") != "online":
            continue
        conf = p.get("conf") or {}
        names = conf.get("customDomains") or conf.get("custom_domains") or []
        if domain in [str(n).strip().lower() for n in names]:
            return True
    return False


def _can_edit(origin_id: str, current_user: dict) -> bool:
    from services.rbac import verify_origin_edit_access
    try:
        verify_origin_edit_access(origin_id, current_user)
        return True
    except HTTPException:
        return False


@router.get("/progress/{origin_id}")
async def get_progress(origin_id: str, current_user: dict = Depends(get_current_user)):
    """Read access (viewers included) sees the status. Only someone who can
    edit the origin gets the verification token and causes side effects:
    DNS checks that mark a domain verified, origin activation, and route
    reconciles. The domain list and verify endpoints were edit-only before;
    a viewer polling this page must not be able to do more than that."""
    from api.domains import format_domain, dns_instructions_for, schedule_site_reconcile
    origin = verify_origin_access(origin_id, current_user)
    can_edit = await asyncio.to_thread(_can_edit, origin_id, current_user)
    mode = origin.get("connection_mode") or ("agent" if origin.get("is_tunnel") else None)

    rows = await asyncio.to_thread(_domains_for_origin, origin_id)

    proxies = []
    if mode != "direct":
        now = time.monotonic()
        force = can_edit and now - _last_frp_poll.get(origin_id, 0) >= FRP_FORCE_POLL_SECONDS
        if force:
            _last_frp_poll[origin_id] = now
        proxies = await origin_service.get_live_proxies(force=force)
    deployed = nginx_site_service.deployed_direct_domains()
    route_failed = nginx_site_service.failed_direct_domains()
    address_ok = mode != "direct" or nginx_site_service.direct_upstream_allowed(origin.get("ip", ""))
    # /tunnels/config-generator mints agent tokens for the domain's owner or a
    # platform admin only (_assert_domain_claimable), not for origin editors.
    can_mint_agent = origin.get("admin_user_id") == current_user.get("user_id") or current_user.get("role") == "admin"

    async def _one(d: dict) -> tuple:
        name = str(d.get("domain_name", "")).lower()
        verified = bool(d.get("dns_verified"))
        current = None
        if not verified and can_edit:
            verified, current = await _check_pending(d)
            if verified:
                d = dict(d, dns_verified=True)
        formatted = await asyncio.to_thread(format_domain, d)

        reconcile = False
        if mode == "direct":
            if not verified:
                conn = {"status": "waiting_dns"}
            elif name in deployed:
                conn = {"status": "connected"}
            elif name in route_failed or not address_ok:
                # nginx refused this site's config, or the address can never
                # be routed (e.g. edited to a hostname); it needs fixing.
                # Other tenants' routes are unaffected.
                conn = {"status": "error"}
            else:
                conn = {"status": "configuring"}
                reconcile = True
        elif _proxy_online_for(name, proxies):
            conn = {"status": "connected"}
        elif mode == "agent" and not verified:
            # P3.2: the agent's tunnel token is issued only once DNS proves
            # the domain is theirs, so the install step waits for that.
            conn = {"status": "waiting_dns"}
        elif mode == "agent":
            conn = {"status": "waiting_agent"}
        else:
            # Origins from before the connect flow: how they are reached is
            # not recorded, so do not claim either way.
            conn = {"status": "unknown"}

        https = {
            "status": formatted.get("ssl_status"),
            "issuer": formatted.get("ssl_issuer"),
            "days_remaining": formatted.get("ssl_days_remaining"),
            "expires_at": formatted.get("ssl_expires_at"),
        }
        token = (d.get("verification_token") or "") if can_edit else ""
        item = {
            "domain_id": formatted.get("domain_id"),
            "domain_name": name,
            "created_at": formatted.get("created_at"),
            "dns": {
                "status": "verified" if verified else "pending",
                "current": current,
                "instructions": dns_instructions_for(name, token),
            },
            "connection": conn,
            "https": https,
            # "unknown" (pre-connect-flow origins) does not hold readiness
            # back: those were judged on DNS + HTTPS before, and still are.
            "ready": verified and conn["status"] in ("connected", "unknown") and https["status"] == "active",
        }
        return item, reconcile

    # One slow DNS answer used to delay every domain after it; check them
    # side by side so a poll takes as long as the slowest domain.
    results = await asyncio.gather(*(_one(d) for d in rows))
    out = [item for item, _ in results]
    want_reconcile = any(r for _, r in results)

    # The origin header said PENDING ("Cancel Setup") next to a LIVE card: an
    # agent origin only turned active when someone opened the Origins list
    # (auto_sync_tunnel_origins). Activate it here as soon as its tunnel is
    # seen. Direct origins are activated by reconcile_site_routes().
    connected_agent = [x for x in out if x["connection"]["status"] == "connected"]
    if can_edit and mode == "agent" and connected_agent and (
        origin.get("status") == "pending" or not origin.get("is_tunnel")
    ):
        update = {
            "status": "active",
            "is_tunnel": True,
            "tunnel_name": connected_agent[0]["domain_name"].replace(".", "-"),
            "updated_at": datetime.now().isoformat() + "Z",
        }
        await asyncio.to_thread(origin_service.db.update_origin, origin_id, update)
        origin_service.invalidate_tenant_cache(origin.get("admin_user_id"))
        origin_service._invalidate_origins_caches()
        origin = dict(origin, **update)

    if can_edit and want_reconcile:
        now = time.monotonic()
        if now - _last_reconcile_request.get(origin_id, 0) >= VERIFY_THROTTLE_SECONDS:
            _last_reconcile_request[origin_id] = now
            schedule_site_reconcile()

    return {
        "origin_id": origin_id,
        "origin_status": origin.get("status"),
        "can_edit": can_edit,
        "can_mint_agent": can_mint_agent,
        "connection_mode": mode,
        # Addresses a direct origin will see the WAF connect from, for the
        # "only accept these in your firewall" tip. Empty = not configured.
        "origin_egress_ips": [ip.strip() for ip in os.getenv("WAF_ORIGIN_EGRESS_IPS", "").split(",") if ip.strip()],
        "origin_address": origin.get("ip"),
        "origin_port": origin.get("port"),
        "origin_scheme": origin.get("origin_scheme"),
        "domains": out,
        "all_ready": bool(out) and all(x["ready"] for x in out),
    }
