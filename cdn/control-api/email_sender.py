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


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM)


def send_otp_email(to_addr: str, code: str) -> bool:
    if not is_configured():
        logger.warning(
            "OTP email not sent to %s -- SMTP_HOST/USER/PASS/FROM not configured", to_addr
        )
        return False

    body = (
        f"Your verification code is: {code}\n\n"
        "This code expires in a few minutes. If you did not request this, "
        "you can ignore this email."
    )
    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = "Your verification code"
    message["From"] = SMTP_FROM
    message["To"] = to_addr

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_addr], message.as_string())
        return True
    except Exception as exc:
        logger.warning("OTP email send failed for %s: %s", to_addr, exc)
        return False
