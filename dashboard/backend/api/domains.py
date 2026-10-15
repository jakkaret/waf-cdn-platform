import re
import time
import asyncio
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import uuid
from datetime import datetime
from services.rbac import get_current_user, verify_origin_ownership, verify_origin_edit_access
from services import audit_log
from services.txn import atomic
from services.dynamodb_service import DynamoDBService, DuplicateDomain
from services.captcha_config import sync_domain_config
from services.dns_service import verify_domain_dns, is_claimable_own_wildcard_subdomain, is_platform_subdomain
from services import nginx_site_service

router = APIRouter(prefix="/api/domains", tags=["Domains"])
db = DynamoDBService()

# asyncio only holds a *weak* reference to a task created by create_task --
# with nothing else referencing it, the task object can be garbage-collected
# mid-run before it finishes. Keeping a strong reference here (discarded via
# the done callback) is the standard workaround.
# https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task
_background_tasks: set = set()


def schedule_site_reconcile() -> None:
    """Best-effort: bring direct-mode nginx routes in line with the database
    now instead of at the site_route_worker's next tick. Never blocks or
    fails the request that triggered it."""
    async def _run():
        try:
            await asyncio.to_thread(nginx_site_service.reconcile_site_routes)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("site route reconcile after domain change failed: %s", exc)
    task = asyncio.create_task(_run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def after_domain_verified(origin_id: str, domain_name: str) -> None:
    """Everything that has to follow a domain becoming verified, in one place.
    The two verify endpoints and services/dns_verification_worker.py each did
    a different subset (the worker did none of it, and the /api/origins/...
    endpoint skipped the TLS allow-list refresh)."""
    try:
        await asyncio.to_thread(sync_domain_config, origin_id, domain_name)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("captcha config sync for %s failed: %s", domain_name, exc)
    invalidate_ssl_allowed_snapshot()
    _refresh_managed_hostmap()
    schedule_site_reconcile()


def _mark_verified(domain_id: str) -> None:
    db.update_domain(domain_id, {"dns_verified": True, "ssl_status": "pending"})


def _refresh_managed_hostmap() -> None:
    """Best-effort: regenerate managed-00-hostmap.conf right away instead of
    waiting for the managed_ruleset_worker's next tick, so a domain that just
    got DNS-verified (or removed) starts (or stops) matching tenant/managed
    rules without a several-minute gap. Never blocks or fails the request
    that triggered it -- the worker will catch up on its own next tick if
    this fails."""
    async def _run():
        try:
            import services.managed_ruleset as mr
            from api.rules import rule_manager  # shared singleton -- same one every other writer uses
            # apply() does blocking file I/O, a DynamoDB scan, and a
            # docker-exec'd nginx -t/reload -- run it off the event loop so
            # it doesn't stall every other request this process is serving.
            await asyncio.to_thread(mr.apply, rule_manager, db)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("managed hostmap refresh after domain change failed: %s", exc)
    task = asyncio.create_task(_run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

# Ruling R7 (task-11-brief.md): domain_name flows into tenant_service's
# ClickHouse LIKE patterns (services/tenant_service.py -> api/analytics.py's
# _build_domain_pattern_sql -> raw f-string interpolation into ClickHouse),
# so it is constrained to a hostname shape at the point it enters the
# system, on *every* write path into domains_table -- not just the endpoint
# newly mounted for T11. Per task-11-brief.md's review (Critical finding):
# the legacy POST /api/domains below applied no validation at all and fed
# the identical sink, so the same _validate_hostname is reused on both
# DomainCreate and DomainCreatePayload rather than only the new one.
#
# This is entry validation as mitigation, not a fix for the underlying
# vulnerability: services/tenant_service.py, api/analytics.py, and
# services/clickhouse_service.py still build ClickHouse queries with
# backslash-replacement escaping only, which a value shaped like
# "x\' OR 1=1 --" already defeats once it reaches that sink (ClickHouse
# reads the resulting "\\'" as one literal backslash followed by a
# string-closing quote). That escaping is a separate, tracked
# parameterization refactor across several call sites -- explicitly out of
# scope here. Constraining domain_name to a hostname shape (no quotes,
# backslashes, '%', or '_') at both entry points closes this specific
# injection path without touching that sink.
_HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+$")


def _assert_platform_subdomain_allowed(domain_name: str, current_user: dict) -> None:
    """F-129: a host at/under the platform apex (*.waf-it-kku.online) resolves to
    the edge and core routes an unknown Host to the tunnel router, so registering
    an unregistered one must be operator-only. Before this gate a non-admin could
    create such a record (even dns_verified=False) and then — because
    _assert_domain_claimable treated the self-created record as proof of ownership
    — mint a tunnel token for it and bind a proxy, taking over a host under the
    platform's own domain. Restrict platform-apex registration AND its auto-verify
    to admins; tenants onboard their own external domains instead."""
    if current_user.get("role") == "admin":
        return
    if is_platform_subdomain(domain_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subdomains of the platform domain are provisioned by the operator; register your own domain instead.",
        )


def _validate_hostname(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 253 or not _HOSTNAME_RE.match(normalized):
        raise ValueError(
            "domain_name must be a valid hostname: labels of letters, digits, "
            "and hyphens (a label may not start or end with a hyphen), each "
            "label at most 63 characters, with at least two labels (e.g. "
            "'example.com'), and at most 253 characters total."
        )
    return normalized


class DomainCreate(BaseModel):
    origin_id: str
    domain_name: str

    @field_validator("domain_name")
    @classmethod
    def _domain_name_must_be_hostname(cls, v: str) -> str:
        return _validate_hostname(v)

class DomainResponse(BaseModel):
    id: str
    origin_id: str
    domain_name: str
    verification_token: str
    dns_verified: bool
    ssl_status: str
    created_at: str

@router.post("", response_model=DomainResponse)
async def create_domain(payload: DomainCreate, current_user: dict = Depends(get_current_user)):
    # 1. Verify that current user can edit the target origin (Team
    # Workspace, 2026-09-22: owner or editor -- adding a domain is a
    # routine, reversible operational change, not a destructive one)
    verify_origin_edit_access(payload.origin_id, current_user)
    # F-129: non-admins may not register a host under the platform apex
    _assert_platform_subdomain_allowed(payload.domain_name, current_user)

    # 2. Check if domain already exists
    assert_domain_available(payload.domain_name)

    # 3. Create domain record
    domain_id = str(uuid.uuid4())
    # Generate verification token
    verification_token = f"waf-token-{uuid.uuid4().hex[:16]}"
    now = datetime.now().isoformat() + "Z"
    
    domain_data = {
        "id": domain_id,
        "origin_id": payload.origin_id,
        "domain_name": payload.domain_name,
        "verification_token": verification_token,
        "dns_verified": False,
        "ssl_status": "none",
        "created_at": now,
        "updated_at": now
    }
    
    _save_new_domain(domain_data)
    return domain_data

@router.get("/origin/{origin_id}", response_model=List[DomainResponse])
async def list_domains_by_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    # Owner or editor (Team Workspace) -- unchanged for a plain viewer,
    # who still cannot reach this endpoint, same as before this feature.
    verify_origin_edit_access(origin_id, current_user)

    try:
        return db.list_domains(origin_id=origin_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query domains: {e}"
        )

@router.delete("/{domain_id}")
async def delete_domain(domain_id: str, current_user: dict = Depends(get_current_user)):
    # 1. Fetch domain
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    # 2. Verify that current user can edit the parent origin
    verify_origin_edit_access(domain["origin_id"], current_user)

    # 3. Delete domain
    try:
        with atomic():
            db.delete_domain(domain_id)
            audit_log.write_audit_event(
                scope_id=domain["origin_id"],
                actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""),
                action="domain.delete",
                summary=f"ลบโดเมน: {domain.get('domain_name', domain_id)}",
                details={"domain_id": domain_id, "domain_name": domain.get("domain_name")},
            )
        invalidate_ssl_allowed_snapshot()
        _refresh_managed_hostmap()
        schedule_site_reconcile()
        return {"status": "success", "message": f"Domain {domain['domain_name']} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{domain_id}/verify")
async def verify_domain_now(domain_id: str, current_user: dict = Depends(get_current_user)):
    # 1. Fetch domain
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    # 2. Verify that current user can edit origin
    verify_origin_edit_access(domain["origin_id"], current_user)
    
    # 3. Trigger check immediately
    domain_name = domain.get("domain_name")
    token = domain.get("verification_token")
    
    # Up to three DNS lookups (dnspython's default lifetime is 5 s each): off
    # the event loop, or every other request waits behind them.
    is_verified = await asyncio.to_thread(verify_domain_dns, domain_name, token)

    if is_verified:
        _mark_verified(domain_id)
        await after_domain_verified(domain["origin_id"], domain_name)
        return {
            "status": "success",
            "dns_verified": True,
            "ssl_status": "pending",
            "message": "Domain successfully verified!"
        }
    else:
        return {
            "status": "failed",
            "dns_verified": False,
            "message": "DNS records check failed. CNAME or TXT verification not found."
        }

# --- on-demand TLS ask endpoint -------------------------------------------
# Snapshot of the domains allowed to obtain a certificate, refreshed lazily.
_SSL_ALLOWED_SNAPSHOT: set = set()
_SSL_SNAPSHOT_AT: float = 0.0
_SSL_SNAPSHOT_LOCK = asyncio.Lock()
SSL_SNAPSHOT_REFRESH_SECONDS = 30.0
MAX_HOSTNAME_LENGTH = 253


def _load_ssl_allowed_from_db() -> set:
    """Domains allowed via persisted DB records:
    1. DNS-verified external domains -- the "bring your own domain" CNAME+TXT
       flow this endpoint originally covered.
    2. cloudwaf tunnel domains (origins_table.tunnel_domains, written by
       api/tunnel.py's issue_agent_token) -- a *different* table from #1;
       this endpoint never checked it at all before 2026-09-21, so a
       cloudwaf-tunneled subdomain could never get a cert issued even once
       the Caddy wiring for this endpoint was fixed.
    """
    # 2026-09-23: archiving an origin is a soft delete on the origin row
    # only -- nothing cascades to its domains, which have no status field
    # of their own. Without the origin-status filter an archived origin's
    # domains stayed in the allow-list forever, so a resource the owner had
    # removed could still obtain and renew TLS certificates indefinitely.
    # verified_hostnames_active() applies that filter and leaves out
    # unverified BYO domains.
    return {
        str(host).strip().lower()
        for host, _origin_id in db.verified_hostnames_active()
        if host
    }


async def _load_ssl_allowed_from_frp() -> set:
    """FRP-issued tunnel domains (api/tunnels.py's config-generator /
    create_tunnel_token) have no persisted "verified" DB record at all --
    they only mint a JWT and rely on frp_webhook_gatekeeper's real-time
    check. A currently-live proxy on FRP's own dashboard (the same signal
    origin_service.py's auto-sync already trusts) is the only real
    evidence that a domain has an active, legitimately-issued tunnel."""
    try:
        import services.origin_service as origin_service
        proxies = await origin_service.get_live_proxies()
    except Exception:
        return set()

    allowed = set()
    for p in proxies:
        if p.get("status") != "online":
            continue
        conf = p.get("conf") or {}
        for d in (conf.get("customDomains") or conf.get("custom_domains") or []):
            if d:
                allowed.add(str(d).strip().lower())
    return allowed


async def _ssl_allowed_set() -> set:
    global _SSL_ALLOWED_SNAPSHOT, _SSL_SNAPSHOT_AT
    now = time.monotonic()
    if _SSL_ALLOWED_SNAPSHOT and (now - _SSL_SNAPSHOT_AT) < SSL_SNAPSHOT_REFRESH_SECONDS:
        return _SSL_ALLOWED_SNAPSHOT
    async with _SSL_SNAPSHOT_LOCK:
        # Another request may have refreshed it while this one waited.
        now = time.monotonic()
        if _SSL_ALLOWED_SNAPSHOT and (now - _SSL_SNAPSHOT_AT) < SSL_SNAPSHOT_REFRESH_SECONDS:
            return _SSL_ALLOWED_SNAPSHOT
        try:
            db_allowed = await asyncio.to_thread(_load_ssl_allowed_from_db)
            frp_allowed = await _load_ssl_allowed_from_frp()
            _SSL_ALLOWED_SNAPSHOT = db_allowed | frp_allowed
            _SSL_SNAPSHOT_AT = now
        except Exception as exc:
            # Keep serving the previous snapshot rather than failing open or
            # failing every handshake because the database hiccuped.
            print(f"check-ssl-allowed: snapshot refresh failed, serving stale set: {exc}")
    return _SSL_ALLOWED_SNAPSHOT


@router.get("/check-ssl-allowed")
async def check_ssl_allowed(domain: str = ""):
    candidate = (domain or "").strip().lower()
    if not candidate:
        raise HTTPException(status_code=400, detail="domain parameter is required")
    # Reject implausible hostnames before touching any shared state.
    if len(candidate) > MAX_HOSTNAME_LENGTH or not _HOSTNAME_RE.match(candidate):
        raise HTTPException(status_code=400, detail="Domain not registered")

    allowed = await _ssl_allowed_set()
    if candidate not in allowed:
        raise HTTPException(status_code=400, detail="Domain not registered")

    return {"status": "allowed", "domain": candidate}


def invalidate_ssl_allowed_snapshot() -> None:
    """Force the next ask to reload -- call after a domain is verified or removed."""
    global _SSL_SNAPSHOT_AT
    _SSL_SNAPSHOT_AT = 0.0


import os

origins_domains_router = APIRouter(prefix="/api/origins", tags=["Domains"])

def format_domain(domain_data: dict) -> dict:
    dns_verified = domain_data.get("dns_verified", False)
    domain_name = domain_data.get("domain_name")

    # 2026-09-21: was `domain_data.get("ssl_status", "none")` only -- that
    # field is never written anywhere in the codebase, so the frontend's
    # `ssl_status || 'ACTIVE'` fallback made every single domain read as a
    # hardcoded, unverified "ACTIVE". services/ssl_cert_monitor.py now
    # writes a real, periodically-probed record per domain into
    # waf_ssl_certs; surface that here instead when one exists.
    cert = None
    if domain_name:
        try:
            # waf_ssl_certs' real key schema is HASH="id" -- see
            # services/ssl_cert_monitor.py's _persist_cert_record for why
            # it's keyed by the domain string itself under "id".
            cert = db.get_ssl_cert(domain_name)
        except Exception:
            cert = None

    if cert:
        ssl_status = "active" if cert.get("status") == "ok" else "error"
        ssl_expires_at = cert.get("not_after")
        ssl_issuer = cert.get("issuer")
        ssl_days_remaining = cert.get("days_remaining")
        ssl_checked_at = cert.get("checked_at")
    else:
        # No probe result yet (worker hasn't reached this domain this cycle,
        # or it isn't in the allowed-set the worker scans) -- "pending" is
        # honest about not knowing, unlike the old silent "ACTIVE" default.
        ssl_status = "pending"
        ssl_expires_at = None
        ssl_issuer = None
        ssl_days_remaining = None
        ssl_checked_at = None

    return {
        "domain_id": domain_data.get("id"),
        "origin_id": domain_data.get("origin_id"),
        "domain_name": domain_name,
        "verification_status": "verified" if dns_verified else "pending",
        "dns_verification_token": domain_data.get("verification_token"),
        "cname_target": os.getenv("WAF_CNAME_TARGET", "cdn.local"),
        "ssl_status": ssl_status,
        "ssl_expires_at": ssl_expires_at,
        "ssl_issuer": ssl_issuer,
        "ssl_days_remaining": ssl_days_remaining,
        "ssl_checked_at": ssl_checked_at,
        "created_at": domain_data.get("created_at"),
    }

@origins_domains_router.get("/{origin_id}/domains")
async def list_domains_under_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    # Owner or editor (Team Workspace, 2026-09-22)
    verify_origin_edit_access(origin_id, current_user)

    items = db.list_domains(origin_id=origin_id)
    formatted = [format_domain(item) for item in items]
    return {"domains": formatted}

class DomainCreatePayload(BaseModel):
    domain_name: str

    @field_validator("domain_name")
    @classmethod
    def _domain_name_must_be_hostname(cls, v: str) -> str:
        return _validate_hostname(v)

def dns_instructions_for(domain_name: str, verification_token: str) -> dict:
    """The CNAME alone both routes traffic to the edge and proves control of
    the name (services/dns_service.verify_domain_dns accepts it), so it is
    the one record a customer has to add. The TXT record is the fallback for
    names that cannot carry a CNAME (a zone apex) or sit behind another proxy."""
    return {
        "cname_record": {
            "type": "CNAME",
            "name": domain_name,
            "value": os.getenv("WAF_CNAME_TARGET", "cdn.local")
        },
        "txt_record": {
            "type": "TXT",
            "name": f"_waf-challenge.{domain_name}",
            "value": verification_token
        },
        "required": ["cname_record"],
    }


def domain_registered(domain_name: str) -> bool:
    return db.get_domain_by_name(domain_name) is not None


def _save_new_domain(domain_data: dict) -> None:
    """Insert a domain row. A name registered meanwhile is a 400, like the
    pre-check; anything else is a 500."""
    try:
        db.create_domain(domain_data)
    except DuplicateDomain as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save domain: {e}"
        )


def assert_domain_available(domain_name: str) -> None:
    if domain_registered(domain_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain name {domain_name} is already registered."
        )


@origins_domains_router.post("/{origin_id}/domains")
async def create_domain_under_origin(origin_id: str, payload: DomainCreatePayload, current_user: dict = Depends(get_current_user)):
    verify_origin_edit_access(origin_id, current_user)
    result = create_domain_record(origin_id, payload.domain_name, current_user)
    if result.get("auto_verified"):
        await after_domain_verified(origin_id, payload.domain_name)
    return result


def create_domain_record(origin_id: str, domain_name: str, current_user: dict) -> dict:
    """Shared by POST /api/origins/{id}/domains and the connect flow
    (api/onboarding.py). The caller has already checked edit access to the
    origin and validated domain_name as a hostname."""
    # F-129: non-admins may not register (nor auto-verify) a host under the
    # platform apex — this is the path whose is_claimable_own_wildcard_subdomain
    # auto-verify made single-label platform subdomains claimable by any tenant.
    _assert_platform_subdomain_allowed(domain_name, current_user)
    assert_domain_available(domain_name)

    domain_id = str(uuid.uuid4())
    verification_token = f"waf-token-{uuid.uuid4().hex[:16]}"
    now = datetime.now().isoformat() + "Z"

    auto_verified = is_claimable_own_wildcard_subdomain(domain_name)

    domain_data = {
        "id": domain_id,
        "origin_id": origin_id,
        "domain_name": domain_name,
        "verification_token": verification_token,
        "dns_verified": auto_verified,
        "ssl_status": "pending" if auto_verified else "none",
        "created_at": now,
        "updated_at": now
    }

    with atomic():
        _save_new_domain(domain_data)
        # The post-verify steps (config sync, TLS allow-list, hostmap, route)
        # are after_domain_verified(), which every caller awaits for an
        # auto-verified result -- one path for all of them.
        audit_log.write_audit_event(
            scope_id=origin_id,
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="domain.create",
            summary=f"เพิ่มโดเมน: {domain_name} " + ("(auto-verified)" if auto_verified else "(รอ verify DNS)"),
            details={"domain_name": domain_name, "auto_verified": bool(auto_verified)},
        )

    if auto_verified:
        return {
            "domain": format_domain(domain_data),
            "dns_instructions": None,
            "auto_verified": True,
        }

    dns_instructions = dns_instructions_for(domain_name, verification_token)
    return {
        "domain": format_domain(domain_data),
        "dns_instructions": dns_instructions,
        "auto_verified": False,
    }

@origins_domains_router.post("/{origin_id}/domains/{domain_id}/verify")
async def verify_domain_now_under_origin(origin_id: str, domain_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_edit_access(origin_id, current_user)
    
    domain = db.get_domain(domain_id)
    if not domain or domain.get("origin_id") != origin_id:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    domain_name = domain.get("domain_name")
    token = domain.get("verification_token")
    
    is_verified = await asyncio.to_thread(verify_domain_dns, domain_name, token)

    if is_verified:
        _mark_verified(domain_id)
        await after_domain_verified(domain["origin_id"], domain_name)
        return {
            "status": "verified",
            "message": "Domain successfully verified!"
        }
    else:
        return {
            "status": "failed",
            "message": "DNS records check failed. CNAME or TXT verification not found."
        }

@origins_domains_router.delete("/{origin_id}/domains/{domain_id}")
async def delete_domain_under_origin(origin_id: str, domain_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_edit_access(origin_id, current_user)

    domain = db.get_domain(domain_id)
    if not domain or domain.get("origin_id") != origin_id:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        with atomic():
            db.delete_domain(domain_id)
            audit_log.write_audit_event(
                scope_id=origin_id,
                actor_user_id=current_user.get("user_id"),
                actor_username=current_user.get("username", ""),
                action="domain.delete",
                summary=f"ลบโดเมน: {domain.get('domain_name', domain_id)}",
                details={"domain_id": domain_id, "domain_name": domain.get("domain_name")},
            )
        invalidate_ssl_allowed_snapshot()
        _refresh_managed_hostmap()
        schedule_site_reconcile()
        return {"status": "success", "message": f"Domain {domain['domain_name']} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
