from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
import asyncio
import ipaddress
import re
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Literal, Optional
from services.rbac import get_current_user, verify_origin_ownership, verify_origin_access, verify_origin_edit_access
import services.origin_service as origin_service
from services.captcha_config import DEFAULT_CONFIG, get_origin_config, save_origin_config
from services.otp_config import (
    DEFAULT_CONFIG as OTP_DEFAULT_CONFIG,
    get_origin_config as get_otp_origin_config,
    save_origin_config as save_otp_origin_config,
)
from services import audit_log, invite_service
from services.txn import atomic
from services.cve_feed import DEFAULT_WINDOW_DAYS, fetch_recent_cves, match_cves_to_origins, select_search_terms

router = APIRouter(prefix="/api/origins", tags=["Origins"])

class OriginCreate(BaseModel):
    label: str
    ip: str
    port: int = Field(ge=1, le=65535)

class OriginUpdate(BaseModel):
    label: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    # CVE Auto-Patch (2026-09-22): self-declared, admin-set -- no real
    # fingerprinting, deliberately (unreliable, out of scope for this
    # feature). Free-form strings like "nginx", "wordpress", "php 8.1".
    tech_stack_tags: Optional[List[str]] = None

    @field_validator("tech_stack_tags")
    @classmethod
    def validate_tech_stack_tags(cls, values):
        if values is None:
            return values
        if len(values) > 20:
            raise ValueError("tech_stack_tags supports at most 20 tags")
        cleaned = []
        for v in values:
            v = str(v).strip()
            if not v:
                continue
            if len(v) > 50:
                raise ValueError("each tech_stack_tag must be 50 characters or fewer")
            cleaned.append(v)
        return cleaned

_ALLOWED_EMAIL_RE = re.compile(r"^([a-z0-9._%+'-]+)?@[a-z0-9-]+(\.[a-z0-9-]+)+$")


class OriginViewerGrant(BaseModel):
    email: str
class CaptchaShieldConfig(BaseModel):
    enabled: bool = False
    engine: Literal["native", "turnstile"] = "native"
    login_paths: List[str] = Field(default_factory=lambda: list(DEFAULT_CONFIG["login_paths"]))
    clearance_ttl: int = Field(default=3600, ge=900, le=43200)
    bypass_ips: List[str] = Field(default_factory=list)
    pow_difficulty: int = Field(default=3, ge=1, le=5)
    mode: Literal["enforce", "log_only"] = "enforce"
    exclude_paths: List[str] = Field(default_factory=list)

    @field_validator("exclude_paths")
    @classmethod
    def validate_exclude_paths(cls, values):
        if len(values) > 20:
            raise ValueError("exclude_paths can contain at most 20 paths")
        for value in values:
            if not isinstance(value, str) or not value.startswith("/") or len(value) > 200:
                raise ValueError("exclude_paths must be absolute paths")
        return [value.strip() for value in values]

    @field_validator("login_paths")
    @classmethod
    def validate_login_paths(cls, values):
        if not values or len(values) > 20:
            raise ValueError("login_paths must contain between 1 and 20 paths")
        for value in values:
            if not isinstance(value, str) or not value.startswith("/") or len(value) > 200:
                raise ValueError("login_paths must be absolute paths")
        return [value.strip() for value in values]

    @field_validator("bypass_ips")
    @classmethod
    def validate_bypass_ips(cls, values):
        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid bypass IP or CIDR: {value}") from exc
        return values

class OtpShieldConfig(BaseModel):
    enabled: bool = False
    login_paths: List[str] = Field(default_factory=lambda: list(OTP_DEFAULT_CONFIG["login_paths"]))
    # 15 min - 30 days: how long a verified visitor is remembered (cdn/control-api
    # otp_engine.CLEARANCE_TTL_RANGE). CAPTCHA above stays capped at 12 h.
    clearance_ttl: int = Field(default=3600, ge=900, le=30 * 86400)
    bypass_ips: List[str] = Field(default_factory=list)
    code_length: int = Field(default=6, ge=4, le=8)
    code_ttl: int = Field(default=300, ge=60, le=1800)
    # Only "email" is implemented server-side right now (see
    # cdn/control-api/email_sender.py); the field is here so the UI/API
    # contract doesn't need to change shape when a second channel ships.
    channel: Literal["email"] = "email"
    mode: Literal["enforce", "log_only"] = "enforce"
    exclude_paths: List[str] = Field(default_factory=list)
    access_mode: Literal["open", "allowlist"] = "open"
    allowed_emails: List[str] = Field(default_factory=list)

    @field_validator("exclude_paths")
    @classmethod
    def validate_exclude_paths(cls, values):
        if len(values) > 20:
            raise ValueError("exclude_paths can contain at most 20 paths")
        for value in values:
            if not isinstance(value, str) or not value.startswith("/") or len(value) > 200:
                raise ValueError("exclude_paths must be absolute paths")
        return [value.strip() for value in values]

    @field_validator("allowed_emails")
    @classmethod
    def validate_allowed_emails(cls, values):
        if len(values) > 200:
            raise ValueError("allowed_emails can contain at most 200 entries")
        cleaned = []
        for value in values:
            entry = str(value).strip().lower()
            if not entry:
                continue
            # "@kku.ac.th" (a whole domain) or "name@gmail.com" (one address)
            if not _ALLOWED_EMAIL_RE.match(entry):
                raise ValueError(f"not an email address or @domain: {value}")
            if entry not in cleaned:
                cleaned.append(entry)
        return cleaned

    @model_validator(mode="after")
    def allowlist_needs_entries(self):
        if self.enabled and self.access_mode == "allowlist" and not self.allowed_emails:
            raise ValueError("allowlist mode needs at least one email address or @domain")
        return self

    @field_validator("login_paths")
    @classmethod
    def validate_login_paths(cls, values):
        if not values or len(values) > 20:
            raise ValueError("login_paths must contain between 1 and 20 paths")
        for value in values:
            if not isinstance(value, str) or not value.startswith("/") or len(value) > 200:
                raise ValueError("login_paths must be absolute paths")
        return [value.strip() for value in values]

    @field_validator("bypass_ips")
    @classmethod
    def validate_bypass_ips(cls, values):
        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid bypass IP or CIDR: {value}") from exc
        return values


@router.post("")
async def create_origin(origin: OriginCreate, current_user: dict = Depends(get_current_user)):
    try:
        data = origin_service.create_origin(
            admin_user_id=current_user.get("user_id"),
            label=origin.label,
            ip=origin.ip,
            port=origin.port
        )
        o = dict(data)
        o["origin_id"] = o.get("id")
        o["health"] = o.get("health", "unknown")
        return o
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/quota")
async def get_quota(current_user: dict = Depends(get_current_user)):
    """Return quota usage for the current user (origins used / max)."""
    info = origin_service.get_quota_info(current_user.get("user_id"))
    return info

def _tunnel_is_online(tunnel_name: str, online_names: set) -> bool:
    """FRP namespaces a proxy's live name with the connection's identity for
    shared/legacy-token clients (e.g. "<legacy-token>.dvwa-waf-it-kku-online"),
    but origin records created at different points in this system's history
    stored `tunnel_name` both with and without that prefix (verified against
    real data: bwapp/dvwa/juice have the bare name, newer records have the
    full prefixed one) -- exact equality silently reported real, online
    tunnels as disconnected. Match tolerantly: exact, or either string is a
    suffix of the other.
    """
    if not tunnel_name:
        return False
    return any(
        tunnel_name == n or n.endswith(tunnel_name) or tunnel_name.endswith(n)
        for n in online_names
    )


def _attach_live_status(origins: list, online_names: set) -> list:
    """`status` is CRUD lifecycle state (active/archived/pending) and is
    never touched here. `live_connected` is a separately computed, read-time
    field for tunnel-backed origins only: is the underlying FRP proxy
    actually online right now. Non-tunnel origins get None (the question
    doesn't apply to them)."""
    out = []
    for origin in origins:
        o = dict(origin)
        o["origin_id"] = o.get("id")
        o["health"] = o.get("health", "unknown")
        if o.get("is_tunnel"):
            o["live_connected"] = _tunnel_is_online(o.get("tunnel_name") or "", online_names)
        else:
            o["live_connected"] = None
        out.append(o)
    return out

@router.get("")
async def list_origins(
    current_user: dict = Depends(get_current_user),
    refresh_status: bool = Query(False, description="Bypass the 60s live-connectivity cache and poll FRP now"),
):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")

    # Auto-sync active tunnels as origins for seamless zero-touch experience
    await origin_service.auto_sync_tunnel_origins(user_id, user_role)

    origins_list = origin_service.get_origins_visible_to_user(user_id)
    online_names = await origin_service.get_live_online_proxy_names(force=refresh_status)
    formatted_origins = _attach_live_status(origins_list, online_names)
    # Sort by created_at descending (newest first)
    formatted_origins.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"origins": formatted_origins}

@router.get("/{origin_id}")
async def get_origin(origin: dict = Depends(verify_origin_access)):
    online_names = await origin_service.get_live_online_proxy_names()
    o = _attach_live_status([origin], online_names)[0]
    return o

# A broad tag ("linux") matches hundreds of CVEs; the page shows the highest
# CVSS scores and says how many there are in total.
ORIGIN_CVES_LIMIT = 50


@router.get("/{origin_id}/cves")
async def get_origin_cves(origin: dict = Depends(verify_origin_access)):
    """CVEs from the NVD feed matching this origin's tech_stack_tags.
    Advisory only: nothing here blocks traffic. Any role that can read the
    origin can read this."""
    searched, skipped = select_search_terms([origin])
    vulnerabilities = await fetch_recent_cves(searched, days=DEFAULT_WINDOW_DAYS)
    matches = match_cves_to_origins(vulnerabilities, [origin])
    matches.sort(key=lambda m: (m.get("cvss_score") is None, -(m.get("cvss_score") or 0)))
    fields = ("cve_id", "severity", "cvss_score", "matched_tag", "description", "published", "last_modified")
    return {
        "cves": [{k: m.get(k) for k in fields} for m in matches[:ORIGIN_CVES_LIMIT]],
        "total": len(matches),
        "keywords_searched": searched,
        "keywords_skipped": skipped,
        "window_days": DEFAULT_WINDOW_DAYS,
    }


@router.put("/{origin_id}")
async def update_origin(
    origin_id: str,
    payload: OriginUpdate,
    origin: dict = Depends(verify_origin_edit_access),
    current_user: dict = Depends(get_current_user),
):
    is_direct = origin.get("connection_mode") == "direct"
    if is_direct and payload.ip:
        # Same rule /api/onboarding/connect applies: an edit must not turn a
        # direct route into a hostname or an internal address (SSRF).
        from services.nginx_site_service import direct_upstream_allowed
        if not direct_upstream_allowed(payload.ip):
            raise HTTPException(
                status_code=400,
                detail="A direct-mode origin needs a public IP address (not a hostname or one of the WAF's own hosts)",
            )
    try:
        # The change and its audit event commit together (PostgreSQL).
        with atomic():
            success = origin_service.update_origin(
                origin_id=origin_id,
                label=payload.label,
                ip=payload.ip,
                port=payload.port,
                tech_stack_tags=payload.tech_stack_tags,
            )
            route_changed = success and is_direct and (payload.ip or payload.port is not None)
            if route_changed and payload.port in (80, 443):
                # Re-derive the scheme for the standard ports; other ports keep
                # the one the connect flow detected.
                origin_service.db.update_origin(
                    origin_id, {"origin_scheme": "https" if payload.port == 443 else "http"})
            if success:
                changed = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
                audit_log.write_audit_event(
                    scope_id=origin_id,
                    actor_user_id=current_user.get("user_id"),
                    actor_username=current_user.get("username", ""),
                    action="origin.update",
                    summary=f"แก้ไข origin: {', '.join(changed.keys()) or 'ไม่มีการเปลี่ยนแปลง'}",
                    details=changed,
                )
        if route_changed:
            from api.domains import schedule_site_reconcile
            schedule_site_reconcile()
        if success:
            return {"status": "success", "message": "Origin updated successfully"}
        raise HTTPException(status_code=500, detail="Failed to update origin")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# See the identical set in api/domains.py: without a strong reference, a
# create_task()'d task can be garbage-collected mid-run.
_background_tasks: set = set()


def _refresh_managed_hostmap() -> None:
    """Best-effort, non-blocking: an archived/restored origin's hosts drop
    out of (or return to) managed-00-hostmap.conf, so re-render it now
    instead of waiting for the managed_ruleset_worker's next tick. See the
    identical helper in api/domains.py for the same reasoning."""
    async def _run():
        try:
            import services.managed_ruleset as mr
            from api.rules import rule_manager  # shared singleton -- same one every other writer uses
            # apply() blocks on file I/O, a DynamoDB scan, and a docker-exec'd
            # nginx -t/reload -- keep it off the event loop.
            await asyncio.to_thread(mr.apply, rule_manager, origin_service.db)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("managed hostmap refresh after origin change failed: %s", exc)
    task = asyncio.create_task(_run())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    # A direct-mode origin's nginx route follows its status the same way.
    from api.domains import schedule_site_reconcile
    schedule_site_reconcile()


@router.delete("/{origin_id}")
async def delete_origin(origin_id: str, origin: dict = Depends(verify_origin_ownership)):
    success = origin_service.delete_origin(origin_id)
    if success:
        _refresh_managed_hostmap()
        return {"status": "success", "message": "Origin deleted successfully"}
    raise HTTPException(status_code=500, detail="Failed to delete origin")

@router.post("/{origin_id}/restore")
async def restore_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    # The whole point of restore is to act on an archived origin.
    verify_origin_ownership(origin_id, current_user, allow_archived=True)
    quota = origin_service.get_quota_info(current_user.get("user_id"))
    if quota["origins"]["at_limit"]:
        raise HTTPException(status_code=400, detail="Cannot restore. Active origin quota exceeded.")
    success = origin_service.restore_origin(origin_id)
    if success:
        _refresh_managed_hostmap()
        return {"status": "success", "message": "Origin restored successfully"}
    raise HTTPException(status_code=500, detail="Failed to restore origin")

@router.get("/{origin_id}/viewers")
async def get_origin_viewers(origin: dict = Depends(verify_origin_ownership)):
    return {"viewers": origin_service.list_origin_viewers(origin.get("id"))}

def _invite_member(request: Request, origin: dict, current_user: dict, email: str, role: str) -> dict:
    """N9/H64: share by invitation. The link goes to the mailbox; access is
    granted only when a signed-in user opens it (api/invites.py). The response
    is the same whether or not the address has an account."""
    email = email.strip().lower()
    if "@" not in email or len(email) > 254:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if email == (current_user.get("email") or "").strip().lower():
        raise HTTPException(status_code=400, detail="You already have access to this origin")
    with atomic():
        token = invite_service.create_invite(origin.get("id"), email, role, current_user["user_id"])
        audit_log.write_audit_event(
            scope_id=origin.get("id"),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action=f"{role}.invite",
            summary=f"เชิญ {role}: {email}",
            details={"email": email},
        )
    # Build the link from configuration, never from the request's Host header,
    # so a spoofed Host cannot point the emailed token at another site.
    link = f"{invite_service.public_app_url()}/invites/accept?token={token}"
    sent = invite_service.send_invite_email(email, origin.get("name") or origin.get("label") or origin.get("id"), role, link)
    return {"status": "invited", "email": email, "role": role, "email_sent": sent}


@router.get("/{origin_id}/invites")
async def list_origin_invites(origin: dict = Depends(verify_origin_ownership)):
    return {"invites": invite_service.pending_invites(origin.get("id"))}


@router.delete("/{origin_id}/invites/{invite_id}")
async def cancel_origin_invite(
    invite_id: str,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    with atomic():
        if not invite_service.cancel_invite(origin.get("id"), invite_id):
            raise HTTPException(status_code=404, detail="Invitation not found")
        audit_log.write_audit_event(
            scope_id=origin.get("id"),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="invite.cancel",
            summary=f"ยกเลิกคำเชิญ {invite_id}",
            details={"invite_id": invite_id},
        )
    return {"status": "cancelled"}


@router.post("/{origin_id}/viewers")
async def add_origin_viewer(
    request: Request,
    payload: OriginViewerGrant,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    return _invite_member(request, origin, current_user, payload.email, "viewer")

@router.delete("/{origin_id}/viewers/{viewer_user_id}")
async def remove_origin_viewer(
    viewer_user_id: str,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    with atomic():
        success = origin_service.db.remove_origin_viewer(origin.get("id"), viewer_user_id)
        member = origin_service.auth_service.get_user_by_id(viewer_user_id)
        if member:  # a link still pending for this person must not restore access
            invite_service.cancel_invites_for(origin.get("id"), member.get("email", ""), "viewer")
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove viewer")
        audit_log.write_audit_event(
            scope_id=origin.get("id"),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="viewer.revoke",
            summary=f"เอา viewer ออก: {viewer_user_id}",
            details={"viewer_user_id": viewer_user_id},
        )
    from services.tenant_service import invalidate_tenant_cache
    invalidate_tenant_cache(viewer_user_id)
    return {"status": "success", "message": "Viewer removed"}

# --- Team Workspace (2026-09-22): editor role, mirrors viewer endpoints
# exactly except for the grant/revoke summary text and which Set on the
# origin item they touch. get/add/remove all stay owner-only
# (verify_origin_ownership) -- deciding who gets write access to an origin
# is itself a management action, not something an editor grants to peers.

@router.get("/{origin_id}/editors")
async def get_origin_editors(origin: dict = Depends(verify_origin_ownership)):
    return {"editors": origin_service.list_origin_editors(origin.get("id"))}

@router.post("/{origin_id}/editors")
async def add_origin_editor(
    request: Request,
    payload: OriginViewerGrant,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    return _invite_member(request, origin, current_user, payload.email, "editor")

@router.delete("/{origin_id}/editors/{editor_user_id}")
async def remove_origin_editor(
    editor_user_id: str,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    if editor_user_id == origin.get("admin_user_id"):
        # The creator is the Admin that can never be removed, so an origin
        # can never end up without one.
        raise HTTPException(status_code=400, detail="The origin's creator cannot be removed")
    with atomic():
        success = origin_service.db.remove_origin_editor(origin.get("id"), editor_user_id)
        member = origin_service.auth_service.get_user_by_id(editor_user_id)
        if member:  # a link still pending for this person must not restore access
            invite_service.cancel_invites_for(origin.get("id"), member.get("email", ""), "editor")
        if not success:
            raise HTTPException(status_code=500, detail="Failed to remove editor")
        audit_log.write_audit_event(
            scope_id=origin.get("id"),
            actor_user_id=current_user.get("user_id"),
            actor_username=current_user.get("username", ""),
            action="editor.revoke",
            summary=f"เอา editor ออก: {editor_user_id}",
            details={"editor_user_id": editor_user_id},
        )
    from services.tenant_service import invalidate_tenant_cache
    invalidate_tenant_cache(editor_user_id)
    return {"status": "success", "message": "Editor removed"}

@router.get("/{origin_id}/audit-log")
async def get_origin_audit_log(origin: dict = Depends(verify_origin_access)):
    """Team Workspace (2026-09-22): owner, editor, or viewer may read the
    audit trail for an origin they can already see -- it only ever shows
    events about actions on this same origin, nothing they couldn't already
    infer from having access to it."""
    events = audit_log.get_audit_log(origin.get("id"))
    return {"events": events}

@router.get("/{origin_id}/captcha")
async def get_captcha_config(origin: dict = Depends(verify_origin_edit_access)):
    try:
        config = get_origin_config(origin.get("id"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"origin_id": origin.get("id"), "captcha_shield": config}

@router.put("/{origin_id}/captcha")
async def update_captcha_config(
    payload: CaptchaShieldConfig,
    origin: dict = Depends(verify_origin_edit_access),
):
    try:
        domains = [
            str(item.get("domain_name", ""))
            for item in origin_service.db.list_domains(origin_id=origin.get("id"), dns_verified=True)
            if item.get("domain_name")
        ]
        config = save_origin_config(origin.get("id"), payload.model_dump(), domains)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save CAPTCHA configuration: {exc}")
    return {"origin_id": origin.get("id"), "captcha_shield": config}

@router.get("/{origin_id}/otp")
async def get_otp_config(origin: dict = Depends(verify_origin_edit_access)):
    try:
        config = get_otp_origin_config(origin.get("id"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"origin_id": origin.get("id"), "otp_shield": config}

@router.put("/{origin_id}/otp")
async def update_otp_config(
    payload: OtpShieldConfig,
    origin: dict = Depends(verify_origin_edit_access),
):
    try:
        domains = [
            str(item.get("domain_name", ""))
            for item in origin_service.db.list_domains(origin_id=origin.get("id"), dns_verified=True)
            if item.get("domain_name")
        ]
        config = save_otp_origin_config(origin.get("id"), payload.model_dump(), domains)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save OTP configuration: {exc}")
    return {"origin_id": origin.get("id"), "otp_shield": config}
