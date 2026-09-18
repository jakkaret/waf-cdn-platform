from fastapi import APIRouter, Depends, HTTPException, status
import ipaddress
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal, Optional
from services.rbac import get_current_user, verify_origin_ownership
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

@router.get("")
async def list_origins(current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")
    
    # Auto-sync active tunnels as origins for seamless zero-touch experience
    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    
    origins_list = origin_service.get_origins_for_user(user_id)
    formatted_origins = []
    for origin in origins_list:
        o = dict(origin)
        o["origin_id"] = o.get("id")
        o["health"] = o.get("health", "unknown")
        formatted_origins.append(o)
    # Sort by created_at descending (newest first)
    formatted_origins.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"origins": formatted_origins}

@router.get("/{origin_id}")
async def get_origin(origin: dict = Depends(verify_origin_ownership)):
    o = dict(origin)
    o["origin_id"] = o.get("id")
    o["health"] = o.get("health", "unknown")
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
