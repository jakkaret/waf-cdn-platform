"""A site's own IP access list and rate limits (2026-10-25).

Owner and editors change them, viewers read them, nobody else sees them
(support only through an active support grant, like every other route under
/api/origins/{origin_id}). The platform-wide lists stay on /api/ip-rules and
/api/rate-limits, for the platform operator only.

Every change is written to the site's audit log; services/site_alerts.py
tells the owner when someone else made it."""
import asyncio
import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from api.rules import rule_manager  # shared singleton -- same rules dir and nginx gate as the other rule writers
from services import audit_log
from services.origin_ip_rules import SiteIpRuleError, SiteIpRuleService
from services.rate_limit_service import RateLimitService
from services.rbac import get_current_user, verify_origin_access, verify_origin_edit_access
from services.shield_sync import HOSTMAP_KEY
from services.txn import atomic

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/origins/{origin_id}", tags=["site-access"])
ip_service = SiteIpRuleService(rule_manager)
rate_service = RateLimitService()

MAX_RATE_RULES_PER_SITE = 20
METHODS = ("ALL", "GET", "POST", "PUT", "PATCH", "DELETE")


def _audit(origin_id: str, user: dict, action: str, summary: str, details: dict) -> None:
    audit_log.write_audit_event(
        scope_id=origin_id, actor_user_id=user.get("user_id"), actor_username=user.get("username", ""),
        action=action, summary=summary, details=details,
    )


# ---- IP access ---------------------------------------------------------------

class SiteIpRuleIn(BaseModel):
    ip: str = Field(..., max_length=64)
    action: Literal["block", "allow"] = "block"
    note: str = Field("", max_length=200)
    hours: Optional[int] = Field(None, ge=1, le=24 * 365, description="Expire after this many hours; empty = permanent")


@router.get("/ip-rules")
async def list_site_ip_rules(origin: dict = Depends(verify_origin_access)):
    from services.origin_ip_rules import list_rules
    return {"rules": await asyncio.to_thread(list_rules, origin["id"])}


@router.post("/ip-rules")
async def add_site_ip_rule(body: SiteIpRuleIn, origin: dict = Depends(verify_origin_edit_access),
                           current_user: dict = Depends(get_current_user)):
    def run():
        with atomic():
            rule = ip_service.add(origin["id"], body.ip, body.action, body.note, body.hours, current_user)
            verb = "บล็อก" if rule["action"] == "block" else "อนุญาต"
            _audit(origin["id"], current_user, "site_ip_rule.add",
                   f"{verb} IP {rule['ip']}" + (f" ({body.hours} ชม.)" if body.hours else ""),
                   {"ip": rule["ip"], "action": rule["action"], "hours": body.hours, "note": rule["note"]})
            return rule
    try:
        return {"rule": await asyncio.to_thread(run)}
    except SiteIpRuleError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.delete("/ip-rules/{rule_id}")
async def delete_site_ip_rule(rule_id: int, origin: dict = Depends(verify_origin_edit_access),
                              current_user: dict = Depends(get_current_user)):
    def run():
        with atomic():
            rule = ip_service.delete(origin["id"], rule_id)
            _audit(origin["id"], current_user, "site_ip_rule.delete", f"เอา IP {rule['ip']} ออกจากรายการ",
                   {"ip": rule["ip"], "action": rule["action"]})
    try:
        await asyncio.to_thread(run)
    except KeyError:
        raise HTTPException(status_code=404, detail="IP rule not found")
    return {"deleted": True}


# ---- rate limits ---------------------------------------------------------------

def _check_pattern(v: str) -> str:
    v = v.strip()
    if not v or len(v) > 200 or not (v == "*" or v.startswith("/")) or any(c in v for c in "\r\n\x00 "):
        raise ValueError("path pattern: * or a path starting with /, e.g. /login or /api/*")
    return v


class SiteRateRuleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    path_pattern: str = Field(..., max_length=200)
    method: str = "ALL"
    limit_count: int = Field(..., ge=1, le=100_000)
    window_seconds: int = Field(..., ge=1, le=3600)

    @field_validator("path_pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        return _check_pattern(v)

    @field_validator("method")
    @classmethod
    def _method(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in METHODS:
            raise ValueError(f"method must be one of {', '.join(METHODS)}")
        return v


class SiteRateRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    path_pattern: Optional[str] = Field(None, max_length=200)
    method: Optional[str] = None
    limit_count: Optional[int] = Field(None, ge=1, le=100_000)
    window_seconds: Optional[int] = Field(None, ge=1, le=3600)
    enabled: Optional[bool] = None

    @field_validator("path_pattern")
    @classmethod
    def _pattern(cls, v: Optional[str]) -> Optional[str]:
        return _check_pattern(v) if v is not None else v

    @field_validator("method")
    @classmethod
    def _method(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().upper()
        if v not in METHODS:
            raise ValueError(f"method must be one of {', '.join(METHODS)}")
        return v


def _site_hosts(origin_id: str) -> set:
    """The site's hosts as control-api sees them (the published host map)."""
    try:
        hostmap = rate_service.redis_client.hgetall(HOSTMAP_KEY) or {}
    except Exception:
        return set()
    return {h for h, oid in hostmap.items() if str(oid) == str(origin_id)}


@router.get("/rate-limits")
async def list_site_rate_limits(origin: dict = Depends(verify_origin_access)):
    return {"rules": await asyncio.to_thread(rate_service.list_rules, origin["id"])}


@router.post("/rate-limits")
async def add_site_rate_limit(body: SiteRateRuleIn, origin: dict = Depends(verify_origin_edit_access),
                              current_user: dict = Depends(get_current_user)):
    def run():
        with atomic():
            if len(rate_service.list_rules(origin["id"])) >= MAX_RATE_RULES_PER_SITE:
                raise ValueError(f"a site can have at most {MAX_RATE_RULES_PER_SITE} rate limits")
            rule = rate_service.add_rule(body.name, body.path_pattern, body.limit_count, body.window_seconds,
                                         body.method, origin_id=origin["id"])
            _audit(origin["id"], current_user, "site_rate_limit.add",
                   f"เพิ่ม rate limit {body.path_pattern} {body.limit_count} ครั้ง/{body.window_seconds} วินาที",
                   {"rule_id": rule["id"], **body.model_dump()})
            return rule
    try:
        return {"rule": await asyncio.to_thread(run)}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.put("/rate-limits/{rule_id}")
async def update_site_rate_limit(rule_id: str, body: SiteRateRuleUpdate, origin: dict = Depends(verify_origin_edit_access),
                                 current_user: dict = Depends(get_current_user)):
    data = body.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(status_code=422, detail="nothing to change")

    def run():
        with atomic():
            rule = rate_service.update_rule(rule_id, data, origin_id=origin["id"])
            if rule:
                _audit(origin["id"], current_user, "site_rate_limit.update",
                       f"แก้ rate limit {rule['path_pattern']} {rule['limit_count']} ครั้ง/{rule['window_seconds']} วินาที"
                       + ("" if rule["enabled"] else " (ปิดอยู่)"), {"rule_id": rule_id, **data})
            return rule
    rule = await asyncio.to_thread(run)
    if not rule:
        raise HTTPException(status_code=404, detail="Rate limit not found")
    return {"rule": rule}


@router.delete("/rate-limits/{rule_id}")
async def delete_site_rate_limit(rule_id: str, origin: dict = Depends(verify_origin_edit_access),
                                 current_user: dict = Depends(get_current_user)):
    def run():
        with atomic():
            current = next((r for r in rate_service.list_rules(origin["id"]) if r["id"] == rule_id), None)
            if not current or not rate_service.delete_rule(rule_id, origin_id=origin["id"]):
                return False
            _audit(origin["id"], current_user, "site_rate_limit.delete",
                   f"ลบ rate limit {current['path_pattern']}", {"rule_id": rule_id})
            return True
    if not await asyncio.to_thread(run):
        raise HTTPException(status_code=404, detail="Rate limit not found")
    return {"deleted": True}


@router.get("/rate-limits/throttled")
async def site_throttled_clients(origin: dict = Depends(verify_origin_access)):
    """Clients counted against any rule on this site's hosts right now."""
    hosts = await asyncio.to_thread(_site_hosts, origin["id"])
    if not hosts:
        return {"throttled_clients": []}
    return {"throttled_clients": await asyncio.to_thread(rate_service.get_throttled_clients, hosts)}
