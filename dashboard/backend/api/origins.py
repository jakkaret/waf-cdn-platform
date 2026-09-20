from fastapi import APIRouter, Depends, HTTPException, status, Query
import ipaddress
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional
from services.rbac import get_current_user, verify_origin_ownership, verify_origin_access
import services.origin_service as origin_service
from services.captcha_config import DEFAULT_CONFIG, get_origin_config, save_origin_config
from services.otp_config import (
    DEFAULT_CONFIG as OTP_DEFAULT_CONFIG,
    get_origin_config as get_otp_origin_config,
    save_origin_config as save_otp_origin_config,
)

router = APIRouter(prefix="/api/origins", tags=["Origins"])

class OriginCreate(BaseModel):
    label: str
    ip: str
    port: int = Field(ge=1, le=65535)

class OriginUpdate(BaseModel):
    label: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)

class OriginViewerGrant(BaseModel):
    email: str
class CaptchaShieldConfig(BaseModel):
    enabled: bool = False
    engine: Literal["native", "turnstile"] = "native"
    login_paths: List[str] = Field(default_factory=lambda: list(DEFAULT_CONFIG["login_paths"]))
    clearance_ttl: int = Field(default=3600, ge=900, le=43200)
    bypass_ips: List[str] = Field(default_factory=list)
    pow_difficulty: int = Field(default=3, ge=1, le=5)

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
    clearance_ttl: int = Field(default=3600, ge=900, le=43200)
    bypass_ips: List[str] = Field(default_factory=list)
    code_length: int = Field(default=6, ge=4, le=8)
    code_ttl: int = Field(default=300, ge=60, le=900)
    # Only "email" is implemented server-side right now (see
    # cdn/control-api/email_sender.py); the field is here so the UI/API
    # contract doesn't need to change shape when a second channel ships.
    channel: Literal["email"] = "email"

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

@router.put("/{origin_id}")
async def update_origin(origin_id: str, payload: OriginUpdate, origin: dict = Depends(verify_origin_ownership)):
    try:
        success = origin_service.update_origin(
            origin_id=origin_id,
            label=payload.label,
            ip=payload.ip,
            port=payload.port
        )
        if success:
            return {"status": "success", "message": "Origin updated successfully"}
        raise HTTPException(status_code=500, detail="Failed to update origin")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{origin_id}")
async def delete_origin(origin_id: str, origin: dict = Depends(verify_origin_ownership)):
    success = origin_service.delete_origin(origin_id)
    if success:
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
        return {"status": "success", "message": "Origin restored successfully"}
    raise HTTPException(status_code=500, detail="Failed to restore origin")

@router.get("/{origin_id}/viewers")
async def get_origin_viewers(origin: dict = Depends(verify_origin_ownership)):
    return {"viewers": origin_service.list_origin_viewers(origin.get("id"))}

@router.post("/{origin_id}/viewers")
async def add_origin_viewer(
    payload: OriginViewerGrant,
    origin: dict = Depends(verify_origin_ownership),
):
    # Reuse origin_service's own AuthService instance rather than
    # constructing a fresh one per request.
    target = origin_service.auth_service.get_user_by_email(payload.email.strip().lower())
    if not target:
        raise HTTPException(status_code=404, detail="No account found with that email")
    target_id = target.get("user_id")
    if target_id == origin.get("admin_user_id"):
        raise HTTPException(status_code=400, detail="You already own this origin")
    success = origin_service.db.add_origin_viewer(origin.get("id"), target_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add viewer")
    from services.tenant_service import invalidate_tenant_cache
    invalidate_tenant_cache(target_id)
    return {"status": "success", "viewer": {"user_id": target_id, "username": target.get("username", ""), "email": target.get("email", "")}}

@router.delete("/{origin_id}/viewers/{viewer_user_id}")
async def remove_origin_viewer(viewer_user_id: str, origin: dict = Depends(verify_origin_ownership)):
    success = origin_service.db.remove_origin_viewer(origin.get("id"), viewer_user_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove viewer")
    from services.tenant_service import invalidate_tenant_cache
    invalidate_tenant_cache(viewer_user_id)
    return {"status": "success", "message": "Viewer removed"}

@router.get("/{origin_id}/captcha")
async def get_captcha_config(origin: dict = Depends(verify_origin_ownership)):
    try:
        config = get_origin_config(origin.get("id"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"origin_id": origin.get("id"), "captcha_shield": config}

@router.put("/{origin_id}/captcha")
async def update_captcha_config(
    payload: CaptchaShieldConfig,
    origin: dict = Depends(verify_origin_ownership),
):
    try:
        from boto3.dynamodb.conditions import Attr
        domains_response = origin_service.db.domains_table.scan(
            FilterExpression=Attr("origin_id").eq(origin.get("id"))
        )
        domains = [
            str(item.get("domain_name", ""))
            for item in domains_response.get("Items", [])
            if item.get("domain_name") and item.get("dns_verified", False)
        ]
        config = save_origin_config(origin.get("id"), payload.model_dump(), domains)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save CAPTCHA configuration: {exc}")
    return {"origin_id": origin.get("id"), "captcha_shield": config}

@router.get("/{origin_id}/otp")
async def get_otp_config(origin: dict = Depends(verify_origin_ownership)):
    try:
        config = get_otp_origin_config(origin.get("id"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return {"origin_id": origin.get("id"), "otp_shield": config}

@router.put("/{origin_id}/otp")
async def update_otp_config(
    payload: OtpShieldConfig,
    origin: dict = Depends(verify_origin_ownership),
):
    try:
        from boto3.dynamodb.conditions import Attr
        domains_response = origin_service.db.domains_table.scan(
            FilterExpression=Attr("origin_id").eq(origin.get("id"))
        )
        domains = [
            str(item.get("domain_name", ""))
            for item in domains_response.get("Items", [])
            if item.get("domain_name") and item.get("dns_verified", False)
        ]
        config = save_otp_origin_config(origin.get("id"), payload.model_dump(), domains)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save OTP configuration: {exc}")
    return {"origin_id": origin.get("id"), "otp_shield": config}
