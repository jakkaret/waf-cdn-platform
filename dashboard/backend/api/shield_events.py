"""Per-origin OTP / CAPTCHA shield activity. An origin's Admins and Viewers
read their own origin's events only (verify_origin_access)."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import services.origin_service as origin_service
from services.clickhouse_service import ClickHouseService
from services.rbac import verify_origin_access, verify_origin_edit_access
from services.shield_events import preview_for_paths, summary_for_origin

router = APIRouter(prefix="/api/origins/{origin_id}/shield-events", tags=["shield-events"])
ch = ClickHouseService()


@router.get("")
async def get_shield_events(
    hours: int = Query(24, ge=1, le=24 * 90),
    limit: int = Query(100, ge=1, le=500),
    origin: dict = Depends(verify_origin_access),
):
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    return summary_for_origin(ch, origin["id"], hours=hours, limit=limit)


class ShieldPreviewRequest(BaseModel):
    login_paths: List[str] = Field(min_length=1, max_length=20)
    exclude_paths: List[str] = Field(default_factory=list, max_length=20)
    hours: int = Field(default=168, ge=1, le=24 * 30)


def _verified_hosts(origin_id: str) -> List[str]:
    from boto3.dynamodb.conditions import Attr
    items = origin_service.db.domains_table.scan(FilterExpression=Attr("origin_id").eq(origin_id)).get("Items", [])
    return [str(i["domain_name"]).strip().lower() for i in items if i.get("domain_name") and i.get("dns_verified")]


@router.post("/preview")
async def preview_shield(body: ShieldPreviewRequest, origin: dict = Depends(verify_origin_edit_access)):
    """Before an Admin saves CAPTCHA/OTP settings: how much of this origin's
    real traffic on those paths would be challenged or blocked."""
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    for p in body.login_paths + body.exclude_paths:
        if not p.startswith("/") or len(p) > 200:
            raise HTTPException(status_code=400, detail="paths must be absolute")
    hosts = _verified_hosts(origin["id"])
    return preview_for_paths(ch, hosts, body.login_paths, body.exclude_paths, body.hours)
