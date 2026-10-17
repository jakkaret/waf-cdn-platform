"""Support tickets and time-limited support access (docs/tickets/support-access.md).

Who may do what:
- open, read, reply, close a ticket: that origin's Owner or Editors
  (rbac.is_origin_admin), or platform support staff (platform role "admin");
- grant or revoke support access: the origin's Owner only (rbac.is_origin_owner),
  like any other decision about who may use the origin;
- support staff use an origin only through a grant, enforced in
  services/rbac.py, never through these routes.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from services import support_service
from services.dynamodb_service import DynamoDBService
from services.rbac import ARCHIVED_ORIGIN_STATUSES, get_current_user, is_origin_admin, is_origin_owner
from services.support_service import SupportError

router = APIRouter(prefix="/api/support", tags=["Support"])


class TicketCreate(BaseModel):
    origin_id: str
    subject: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., min_length=1, max_length=5000)


class MessageCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class GrantCreate(BaseModel):
    level: str = Field("viewer", pattern="^(viewer|editor)$")
    hours: int = Field(24, ge=support_service.MIN_GRANT_HOURS, le=support_service.MAX_GRANT_HOURS)
    confirm_edit: bool = False


def _is_staff(user: dict) -> bool:
    return user.get("role") == "admin"


def _live_origin(origin_id: str) -> Optional[dict]:
    origin = DynamoDBService().get_origin_by_id(origin_id)
    if not origin or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        return None
    return origin


def _admin_origin_ids(user_id: str) -> list:
    from services import origin_service
    return [str(o.get("id") or o.get("origin_id")) for o in origin_service.get_origins_visible_to_user(user_id)
            if is_origin_admin(o, user_id) and o.get("status") not in ARCHIVED_ORIGIN_STATUSES]


def _ticket_for(ticket_id: str, user: dict, owner_only: bool = False) -> tuple:
    """(ticket, origin) when the caller may see it; 404 otherwise (no existence oracle)."""
    ticket = support_service.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    origin = DynamoDBService().get_origin_by_id(ticket["origin_id"])
    owner = bool(origin) and is_origin_admin(origin, user.get("user_id"))
    if owner_only:
        if not (origin and is_origin_owner(origin, user.get("user_id"))):
            can_see = owner or _is_staff(user)  # an Editor or support sees the ticket: say why
            raise HTTPException(status_code=403 if can_see else 404,
                                detail="Only the owner of this origin can do that" if can_see else "Ticket not found")
    elif not owner and not _is_staff(user):
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket, origin


def _bad(exc: SupportError):
    raise HTTPException(status_code=400, detail=str(exc))


@router.get("/origins")
def my_origins(current_user: dict = Depends(get_current_user)):
    """Origins the caller can open a ticket for (those they are an Admin of)."""
    from services import origin_service
    uid = current_user.get("user_id")
    return {"origins": [{"id": str(o.get("id") or o.get("origin_id")), "label": o.get("label") or o.get("name")}
                        for o in origin_service.get_origins_visible_to_user(uid)
                        if is_origin_admin(o, uid) and o.get("status") not in ARCHIVED_ORIGIN_STATUSES]}


@router.post("/tickets", status_code=201)
def open_ticket(req: TicketCreate, current_user: dict = Depends(get_current_user)):
    origin = _live_origin(req.origin_id)
    if not origin or not is_origin_admin(origin, current_user.get("user_id")):
        raise HTTPException(status_code=404, detail="Origin not found")
    try:
        return support_service.create_ticket(req.origin_id, current_user["user_id"], req.subject, req.message)
    except SupportError as e:
        _bad(e)


@router.get("/tickets")
def list_tickets(current_user: dict = Depends(get_current_user)):
    if _is_staff(current_user):
        return {"tickets": support_service.list_tickets(None), "staff": True}
    return {"tickets": support_service.list_tickets(_admin_origin_ids(current_user["user_id"])), "staff": False}


@router.get("/tickets/{ticket_id}")
def ticket_detail(ticket_id: str, current_user: dict = Depends(get_current_user)):
    ticket, origin = _ticket_for(ticket_id, current_user)
    return {
        "ticket": ticket,
        "origin": {"id": ticket["origin_id"], "label": (origin or {}).get("label")},
        "messages": support_service.messages(ticket_id),
        "grants": support_service.grants(ticket_id),
        "access_log": support_service.access_log(ticket_id),
        "can_grant": bool(origin) and is_origin_owner(origin, current_user.get("user_id")),
        "staff": _is_staff(current_user),
    }


@router.post("/tickets/{ticket_id}/messages", status_code=201)
def reply(ticket_id: str, req: MessageCreate, current_user: dict = Depends(get_current_user)):
    ticket, origin = _ticket_for(ticket_id, current_user)
    as_support = _is_staff(current_user) and not (origin and is_origin_admin(origin, current_user.get("user_id")))
    try:
        return support_service.add_message(ticket, current_user["user_id"], req.body, as_support)
    except SupportError as e:
        _bad(e)


@router.post("/tickets/{ticket_id}/close")
def close(ticket_id: str, current_user: dict = Depends(get_current_user)):
    ticket, _ = _ticket_for(ticket_id, current_user)
    support_service.close_ticket(ticket, current_user["user_id"])
    return {"status": "closed"}


@router.post("/tickets/{ticket_id}/grant", status_code=201)
def grant(ticket_id: str, req: GrantCreate, current_user: dict = Depends(get_current_user)):
    ticket, origin = _ticket_for(ticket_id, current_user, owner_only=True)
    if not _live_origin(ticket["origin_id"]):
        raise HTTPException(status_code=404, detail="Origin not found")
    try:
        return support_service.grant_access(ticket, current_user["user_id"], req.level, req.hours, req.confirm_edit)
    except SupportError as e:
        _bad(e)


@router.delete("/tickets/{ticket_id}/grant")
def revoke(ticket_id: str, current_user: dict = Depends(get_current_user)):
    ticket, _ = _ticket_for(ticket_id, current_user, owner_only=True)
    return {"revoked": support_service.revoke_access(ticket, current_user["user_id"])}
