"""Thin SMTP wrapper for OTP delivery. Stdlib only (smtplib/email) -- no new
pip dependency, matching this project's preference for reuse over new deps.

No real SMTP account has been configured on this deployment yet -- send_otp_email()
fails loud (returns False, logs the reason) rather than pretending an email
went out. Wire SMTP_HOST/PORT/USER/PASS/FROM in the environment once real
credentials exist (see docker-compose.yml's control-api service).
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")

# Integration tests (tests/integration) sign in with addresses under a QA-only
# domain, e.g. qa-admin@qa.waf-it-kku.online. Mail to those domains goes to a local
# capture server (Mailpit, no auth, no TLS) instead of the real SMTP relay, so
# the tests can read the code. Every other recipient is unaffected. Unset =
# feature off.
QA_MAIL_DOMAINS = {d.strip().lower() for d in os.getenv("QA_MAIL_DOMAINS", "").split(",") if d.strip()}
QA_SMTP_HOST = os.getenv("QA_SMTP_HOST", "")
QA_SMTP_PORT = int(os.getenv("QA_SMTP_PORT", "1025"))


def _is_qa_recipient(to_addr: str) -> bool:
    domain = to_addr.rsplit("@", 1)[-1].strip().lower() if "@" in to_addr else ""
    return bool(QA_SMTP_HOST and domain and domain in QA_MAIL_DOMAINS)


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM)


def send_otp_email(to_addr: str, code: str, ttl_seconds: int | None = None) -> bool:
    qa = _is_qa_recipient(to_addr)
    if not qa and not is_configured():
        logger.warning(
            "OTP email not sent to %s -- SMTP_HOST/USER/PASS/FROM not configured", to_addr
        )
        return False

    minutes = max(1, round(ttl_seconds / 60)) if ttl_seconds else None
    expires = f"This code expires in {minutes} minute{'s' if minutes != 1 else ''}." if minutes else "This code expires in a few minutes."
    body = (
        f"Your verification code is: {code}\n\n"
        f"{expires} If you did not request this, "
        "you can ignore this email."
    )
    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = "Your verification code"
    message["From"] = SMTP_FROM or "waf-otp@qa.waf-it-kku.online"
    message["To"] = to_addr

    if qa:
        try:
            with smtplib.SMTP(QA_SMTP_HOST, QA_SMTP_PORT, timeout=5) as server:
                server.sendmail(message["From"], [to_addr], message.as_string())
            return True
        except Exception as exc:
            logger.warning("QA OTP email send failed for %s: %s", to_addr, exc)
            return False

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_addr], message.as_string())
        return True
    except Exception as exc:
        logger.warning("OTP email send failed for %s: %s", to_addr, exc)
        return False
