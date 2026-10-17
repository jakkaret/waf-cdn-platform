"""Support tickets and time-limited support access (docs/tickets/support-access.md).

An origin admin opens a ticket for that origin and may grant the platform
support team (platform admins, role "admin") temporary access to that one
origin: "viewer" reads, "editor" also passes verify_origin_edit_access. A grant
never passes verify_origin_ownership (delete/restore, members, tunnel
credentials). No account is created: access rides on each staff member's own
account, and every use is written to support_access_log for the owner to see.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from db import pool


def _scope_changed() -> None:
    # Admin log/alert visibility follows the grants (tenant_service).
    from services.tenant_service import invalidate_admin_scope_cache
    invalidate_admin_scope_cache()

logger = logging.getLogger(__name__)

GRANT_LEVELS = ("viewer", "editor")
MIN_GRANT_HOURS = 1
MAX_GRANT_HOURS = 72
# One read entry per staff member per grant in this window, so browsing an
# origin page (several API calls) does not flood the owner's audit view.
READ_LOG_WINDOW_MINUTES = 5


class SupportError(ValueError):
    """Bad request on a ticket (closed ticket, invalid level or duration)."""


def _row(r: Optional[dict]) -> Optional[dict]:
    """JSON-ready row: UUIDs as strings, timestamps as ISO 8601."""
    if r is None:
        return None
    out = {}
    for k, v in r.items():
        if isinstance(v, uuid.UUID):
            v = str(v)
        elif isinstance(v, datetime):
            v = v.isoformat()
        out[k] = v
    return out


# ------------------------------------------------------------------ tickets

def create_ticket(origin_id: str, user_id: str, subject: str, message: str) -> dict:
    subject, message = (subject or "").strip(), (message or "").strip()
    if not subject or len(subject) > 200:
        raise SupportError("subject must be 1-200 characters")
    if not message or len(message) > 5000:
        raise SupportError("message must be 1-5000 characters")
    with pool.transaction() as conn:
        t = conn.execute(
            "INSERT INTO support_tickets (origin_id, opened_by, subject) VALUES (%s, %s, %s) RETURNING *",
            (origin_id, user_id, subject)).fetchone()
        conn.execute(
            "INSERT INTO support_ticket_messages (ticket_id, author_id, is_support, body) VALUES (%s, %s, false, %s)",
            (t["ticket_id"], user_id, message))
    return _row(t)


def get_ticket(ticket_id: str) -> Optional[dict]:
    try:
        return _row(pool.q1("SELECT * FROM support_tickets WHERE ticket_id = %s", (ticket_id,)))
    except Exception:  # malformed uuid -> not found
        return None


def list_tickets(origin_ids: Optional[List[str]] = None) -> List[dict]:
    """All tickets (origin_ids None, support view) or those of the given origins."""
    base = ("SELECT t.*, o.label AS origin_label, "
            "(SELECT count(*) FROM support_ticket_messages m WHERE m.ticket_id = t.ticket_id) AS message_count, "
            "EXISTS (SELECT 1 FROM support_grants g WHERE g.ticket_id = t.ticket_id AND g.revoked_at IS NULL "
            "        AND g.expires_at > now()) AS access_granted "
            "FROM support_tickets t JOIN origins o ON o.id = t.origin_id ")
    if origin_ids is None:
        rows = pool.q(base + "ORDER BY (t.status = 'open') DESC, t.updated_at DESC")
    elif not origin_ids:
        return []
    else:
        rows = pool.q(base + "WHERE t.origin_id = ANY(%s::uuid[]) ORDER BY (t.status = 'open') DESC, t.updated_at DESC",
                      (list(origin_ids),))
    return [_row(r) for r in rows]


def messages(ticket_id: str) -> List[dict]:
    rows = pool.q(
        "SELECT m.message_id, m.author_id, m.is_support, m.body, m.created_at, u.username AS author_name "
        "FROM support_ticket_messages m LEFT JOIN users u ON u.user_id = m.author_id "
        "WHERE m.ticket_id = %s ORDER BY m.created_at", (ticket_id,))
    return [_row(r) for r in rows]


def add_message(ticket: dict, user_id: str, body: str, is_support: bool) -> dict:
    if ticket["status"] != "open":
        raise SupportError("ticket is closed")
    body = (body or "").strip()
    if not body or len(body) > 5000:
        raise SupportError("message must be 1-5000 characters")
    with pool.transaction() as conn:
        m = conn.execute(
            "INSERT INTO support_ticket_messages (ticket_id, author_id, is_support, body) VALUES (%s, %s, %s, %s) "
            "RETURNING message_id, author_id, is_support, body, created_at",
            (ticket["ticket_id"], user_id, is_support, body)).fetchone()
        conn.execute("UPDATE support_tickets SET updated_at = now() WHERE ticket_id = %s", (ticket["ticket_id"],))
    return _row(m)


def close_ticket(ticket: dict, user_id: str) -> None:
    """Close the ticket and end any support access it granted."""
    with pool.transaction() as conn:
        conn.execute("UPDATE support_tickets SET status = 'closed', closed_at = now(), closed_by = %s, "
                     "updated_at = now() WHERE ticket_id = %s AND status = 'open'", (user_id, ticket["ticket_id"]))
        conn.execute("UPDATE support_grants SET revoked_at = now(), revoked_by = %s "
                     "WHERE ticket_id = %s AND revoked_at IS NULL", (user_id, ticket["ticket_id"]))
    _scope_changed()


# ------------------------------------------------------------------ grants

def grant_access(ticket: dict, user_id: str, level: str, hours: int, confirm_edit: bool) -> dict:
    """Replace the ticket's grant with a new one. Editor needs confirm_edit."""
    if ticket["status"] != "open":
        raise SupportError("ticket is closed")
    if level not in GRANT_LEVELS:
        raise SupportError("level must be viewer or editor")
    if level == "editor" and not confirm_edit:
        raise SupportError("editor access needs explicit confirmation (confirm_edit)")
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        raise SupportError("hours must be a number")
    if not MIN_GRANT_HOURS <= hours <= MAX_GRANT_HOURS:
        raise SupportError(f"hours must be {MIN_GRANT_HOURS}-{MAX_GRANT_HOURS}")
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    with pool.transaction() as conn:
        conn.execute("UPDATE support_grants SET revoked_at = now(), revoked_by = %s "
                     "WHERE ticket_id = %s AND revoked_at IS NULL", (user_id, ticket["ticket_id"]))
        g = conn.execute(
            "INSERT INTO support_grants (ticket_id, origin_id, level, granted_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING *",
            (ticket["ticket_id"], ticket["origin_id"], level, user_id, expires)).fetchone()
        conn.execute("UPDATE support_tickets SET updated_at = now() WHERE ticket_id = %s", (ticket["ticket_id"],))
    _scope_changed()
    return _row(g)


def revoke_access(ticket: dict, user_id: str) -> int:
    n = pool.exec_("UPDATE support_grants SET revoked_at = now(), revoked_by = %s "
                   "WHERE ticket_id = %s AND revoked_at IS NULL", (user_id, ticket["ticket_id"]))
    _scope_changed()
    return n


def grants(ticket_id: str) -> List[dict]:
    rows = pool.q("SELECT *, (revoked_at IS NULL AND expires_at > now()) AS active FROM support_grants "
                  "WHERE ticket_id = %s ORDER BY created_at DESC", (ticket_id,))
    return [_row(r) for r in rows]


def access_log(ticket_id: str, limit: int = 200) -> List[dict]:
    rows = pool.q(
        "SELECT l.at, l.kind, l.staff_id, u.username AS staff_name, g.level "
        "FROM support_access_log l JOIN support_grants g ON g.grant_id = l.grant_id "
        "LEFT JOIN users u ON u.user_id = l.staff_id "
        "WHERE g.ticket_id = %s ORDER BY l.at DESC LIMIT %s", (ticket_id, int(limit)))
    return [_row(r) for r in rows]


def active_grant(origin_id: str) -> Optional[dict]:
    """The strongest unexpired, unrevoked grant on this origin, if any."""
    try:
        return pool.q1(
            "SELECT grant_id, level FROM support_grants WHERE origin_id = %s AND revoked_at IS NULL "
            "AND expires_at > now() ORDER BY (level = 'editor') DESC, expires_at DESC LIMIT 1", (origin_id,))
    except Exception as exc:
        logger.warning("support grant lookup failed for %s: %s", origin_id, exc)
        return None  # fail closed: no support access


def log_use(grant_id, origin_id: str, staff_id: str, kind: str) -> None:
    """Record a grant use; reads are folded to one per staff member per window.
    Raises on failure: callers deny access rather than allow an unlogged use."""
    if kind == "read":
        pool.exec_(
            "INSERT INTO support_access_log (grant_id, origin_id, staff_id, kind) "
            "SELECT %s, %s, %s, 'read' WHERE NOT EXISTS (SELECT 1 FROM support_access_log "
            "WHERE grant_id = %s AND staff_id = %s AND kind = 'read' "
            "AND at > now() - make_interval(mins => %s))",
            (grant_id, origin_id, staff_id, grant_id, staff_id, READ_LOG_WINDOW_MINUTES))
    else:
        pool.exec_("INSERT INTO support_access_log (grant_id, origin_id, staff_id, kind) VALUES (%s, %s, %s, %s)",
                   (grant_id, origin_id, staff_id, kind))
