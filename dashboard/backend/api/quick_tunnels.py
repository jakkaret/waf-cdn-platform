"""Quick tunnels (services/quick_tunnel.py): a platform-named host such as
t-ab3k9mxq.tunnel.originweb.site for a user with no domain of their own.

Only the port is taken from the client; the name never is. The agent command
for a quick tunnel comes from the existing GET /api/tunnels/config-generator,
like any other tunnel domain the user owns.
"""
import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

import services.origin_service as origin_service
from services import quick_tunnel, shield_sync
from services.rbac import get_current_user, require_verified_email

router = APIRouter(prefix="/api/tunnels/quick", tags=["Private Tunnels"])


class CreateQuickTunnel(BaseModel):
    # extra="forbid": a "domain" or "name" sent by a client is refused, not ignored.
    model_config = ConfigDict(extra="forbid")
    port: int = Field(3000, ge=1, le=65535)


def _raise(exc: quick_tunnel.QuickTunnelError):
    raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.get("")
async def list_quick_tunnels(
    scope: Literal["my", "all"] = Query("my", description="'all' lists every user's quick tunnels (admin only)"),
    current_user: dict = Depends(get_current_user),
):
    is_admin = current_user.get("role") == "admin"
    view_all = is_admin and scope == "all"
    # force: the shared 60 s proxy cache showed an agent that had just
    # connected as offline for up to a minute (frps is local, the call is cheap).
    online = quick_tunnel.online_hosts(await origin_service.get_live_proxies(force=True))
    user_id = str(current_user.get("user_id"))
    items = await asyncio.to_thread(quick_tunnel.list_tunnels, None if view_all else user_id, online)
    if view_all:
        # An admin sees another user's name, owner and status (enough to act
        # on an abuse report), not the private port behind it.
        for item in items:
            if item["owner_id"] != user_id:
                item["port"] = None
    return {
        "zone": quick_tunnel.ZONE,
        "limit": quick_tunnel.PER_USER,
        "idle_days": quick_tunnel.IDLE_DAYS,
        "scope": "all" if view_all else "my",
        "is_admin": is_admin,
        "tunnels": items,
    }


@router.post("", dependencies=[Depends(require_verified_email("agent_token"))])
async def create_quick_tunnel(payload: CreateQuickTunnel, current_user: dict = Depends(get_current_user)):
    from api.domains import after_domain_verified
    try:
        created = await asyncio.to_thread(quick_tunnel.create, current_user, payload.port)
    except quick_tunnel.QuickTunnelError as exc:
        _raise(exc)
    await after_domain_verified(created["origin_id"], created["domain_name"])
    return dict(created, url=f"https://{created['domain_name']}")


@router.delete("/{origin_id}")
async def delete_quick_tunnel(origin_id: str, current_user: dict = Depends(get_current_user)):
    """The owner removes their own; an admin removes anyone's (abuse). Anything
    else is a 404, the same as an unknown id."""
    is_admin = current_user.get("role") == "admin"
    tunnel = await asyncio.to_thread(quick_tunnel.get, origin_id)
    if not tunnel or not (tunnel["owner_id"] == str(current_user.get("user_id")) or is_admin):
        raise HTTPException(status_code=404, detail="Quick tunnel not found")
    reason = "removed by owner" if tunnel["owner_id"] == str(current_user.get("user_id")) else "removed by admin"
    await asyncio.to_thread(quick_tunnel.remove, origin_id, current_user, reason)

    from api.domains import invalidate_ssl_allowed_snapshot, _refresh_managed_hostmap, schedule_site_reconcile
    from api.tunnels import _TUNNELS_CACHE
    _TUNNELS_CACHE.clear()
    await asyncio.to_thread(shield_sync.reconcile_quietly, quick_tunnel.db)
    invalidate_ssl_allowed_snapshot()
    _refresh_managed_hostmap()
    schedule_site_reconcile()
    return {"status": "success", "domain_name": tunnel["domain_name"]}
