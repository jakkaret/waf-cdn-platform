"""Outgoing mail for the dashboard (invitations, verification and reset codes).

SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / SMTP_FROM come from the
environment; with any of them missing nothing is sent and send_mail() returns
False. Addresses under reserved example/test domains are never sent to: the
production gates register throwaway accounts like pgmig-...@example.org, and
every bounce from them would count against the sending account's reputation.
"""
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)

# RFC 2606 / 6761 names that never belong to a real mailbox.
_RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}
_RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost", ".local")


def deliverable(to_addr: str) -> bool:
    domain = to_addr.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in to_addr else ""
    if not domain:
        return False
    if domain in _RESERVED_DOMAINS or any(domain.endswith("." + d) for d in _RESERVED_DOMAINS):
        return False
    return not domain.endswith(_RESERVED_SUFFIXES)


def send_mail(to_addr: str, subject: str, text: str, html: Optional[str] = None) -> bool:
    """Best effort; returns False (and logs why) when the mail did not go out."""
    if not deliverable(to_addr):
        logger.info("mail to a reserved domain skipped: %s", subject)
        return False
    host, user, password, sender = (os.getenv(k, "") for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_FROM"))
    if not (host and user and password and sender):
        logger.warning("mail not sent (%s): SMTP is not configured", subject)
        return False
    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
        msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as s:
            s.starttls()
            s.login(user, password)
            s.send_message(msg)
        return True
    except Exception as exc:
        logger.warning("mail to %s failed (%s): %s", to_addr, subject, exc)
        return False
