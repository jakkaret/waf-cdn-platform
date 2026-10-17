"""Origin sharing by invitation (N9/H64).

Adding a viewer or editor no longer grants access to whichever account holds
that email address: anyone could have registered it first, and registration
does not verify mailboxes. Instead an invitation link goes to the mailbox, and
access is granted to the signed-in user who opens it. The token is the proof
of mailbox access, so only its SHA-256 is stored.
"""
import hashlib
import logging
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Optional, Tuple

from db import pool

logger = logging.getLogger(__name__)

INVITE_TTL_DAYS = 7


def public_app_url() -> str:
    """Base URL for links in invitation emails (PUBLIC_APP_URL, https only)."""
    url = (os.getenv("PUBLIC_APP_URL") or "https://waf-it-kku.online").rstrip("/")
    if not url.startswith("https://"):
        raise RuntimeError("PUBLIC_APP_URL must be an https URL")
    return url


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_invite(origin_id: str, email: str, role: str, invited_by: str) -> str:
    """Store a pending invitation and return the raw token (sent by email only)."""
    if role not in ("viewer", "editor"):
        raise ValueError("role must be viewer or editor")
    token = secrets.token_urlsafe(32)
    pool.exec_(
        "INSERT INTO origin_invites (origin_id, email, role, token_hash, invited_by, expires_at) "
        "VALUES (%s, %s, %s, %s, %s, now() + make_interval(days => %s))",
        (origin_id, email.strip().lower(), role, _hash(token), invited_by, INVITE_TTL_DAYS),
    )
    return token


def accept_invite(token: str, user_id: str) -> Optional[Tuple[str, str]]:
    """Grant the invited role to user_id. Returns (origin_id, role), or None if
    the token is unknown, expired or already used. One use per invitation."""
    with pool.transaction():
        # The invitation is only as good as its source: the origin must still
        # be live and the inviter must still be its Owner (only the Owner
        # manages the team). Archiving the origin voids pending links.
        row = pool.q1(
            "UPDATE origin_invites i SET accepted_at = now(), accepted_by = %s "
            "FROM origins o "
            "WHERE i.token_hash = %s AND i.accepted_at IS NULL AND i.expires_at > now() "
            "AND o.id = i.origin_id AND o.status NOT IN ('archived', 'deleted') "
            "AND i.invited_by IS NOT NULL "
            "AND o.admin_user_id = i.invited_by "
            "RETURNING i.origin_id, i.role, i.invited_by",
            (user_id, _hash(token or "")),
        )
        if not row:
            return None
        pool.exec_(
            "INSERT INTO origin_members (origin_id, user_id, role, granted_by) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT DO NOTHING",
            (row["origin_id"], user_id, row["role"], row["invited_by"]),
        )
    return str(row["origin_id"]), row["role"]


def cancel_invite(origin_id: str, invite_id: str) -> bool:
    return pool.exec_(
        "DELETE FROM origin_invites WHERE origin_id = %s AND invite_id = %s AND accepted_at IS NULL",
        (origin_id, invite_id)) > 0


def cancel_invites_for(origin_id: str, user_id: str, role: str) -> int:
    """Revoking a member voids every link still pending for them: links to the
    account's own address, and links to any address this user accepted an
    invitation of before (a link is proof of a mailbox, not of an account)."""
    return pool.exec_(
        "DELETE FROM origin_invites p WHERE p.origin_id = %s AND p.role = %s AND p.accepted_at IS NULL "
        "AND (p.email = (SELECT lower(email) FROM users WHERE user_id = %s) "
        "     OR p.email IN (SELECT a.email FROM origin_invites a "
        "                    WHERE a.origin_id = %s AND a.accepted_by = %s))",
        (origin_id, role, user_id, origin_id, user_id))


def pending_invites(origin_id: str) -> list:
    return [
        {"invite_id": str(r["invite_id"]), "email": r["email"], "role": r["role"],
         "expires_at": r["expires_at"].isoformat()}
        for r in pool.q(
            "SELECT invite_id, email, role, expires_at FROM origin_invites "
            "WHERE origin_id = %s AND accepted_at IS NULL AND expires_at > now() ORDER BY created_at",
            (origin_id,))
    ]


def send_invite_email(to_addr: str, origin_label: str, role: str, link: str) -> bool:
    """Best effort; returns False (and logs why) when SMTP is not configured."""
    host, user, password, sender = (os.getenv(k, "") for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_FROM"))
    if not (host and user and password and sender):
        logger.warning("invite email not sent: SMTP is not configured")
        return False
    body = (
        f"You were invited to {role} the site \"{origin_label}\" on the WAF dashboard.\n\n"
        f"Open this link while signed in to accept (valid {INVITE_TTL_DAYS} days):\n{link}\n\n"
        "If you did not expect this, ignore this email."
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "WAF dashboard invitation"
    msg["From"] = sender
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as s:
            s.starttls()
            s.login(user, password)
            s.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("invite email to %s failed: %s", to_addr, exc)
        return False
