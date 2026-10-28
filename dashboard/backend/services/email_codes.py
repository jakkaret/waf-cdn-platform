"""6-digit codes mailed to an account's address: purpose "verify" proves the
mailbox after sign-up, purpose "reset" sets a new password.

One live code per account and purpose (a new code replaces the old one). A
code lives CODE_TTL_MINUTES, works once, and is void after MAX_ATTEMPTS wrong
guesses. Only an HMAC of it is stored, keyed from the JWT secret: a plain hash
of six digits would fall to a million guesses offline. Sending is limited per
account (RESEND_COOLDOWN_SECONDS between codes, HOURLY_SENDS an hour) on top of
the per-IP limits on the endpoints.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
from typing import Optional, Tuple

from db import pool
from services import mailer

logger = logging.getLogger(__name__)

PURPOSES = ("verify", "reset")
CODE_TTL_MINUTES = 10
MAX_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60
HOURLY_SENDS = 5


def _key() -> bytes:
    secret = os.getenv("JWT_SECRET_KEY", "")
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY is not set")
    return hashlib.sha256((secret + "|email-codes").encode()).digest()


def _digest(user_id: str, purpose: str, code: str) -> str:
    return hmac.new(_key(), f"{user_id}|{purpose}|{code}".encode(), hashlib.sha256).hexdigest()


def issue(user_id: str, purpose: str) -> Tuple[Optional[str], int]:
    """A new code for the account, replacing any earlier one: (code, 0). While
    the cooldown or the hourly cap holds: (None, seconds to wait)."""
    assert purpose in PURPOSES
    with pool.transaction():
        wait = pool.q1(
            "SELECT greatest(0, ceil(extract(epoch FROM created_at + make_interval(secs => %s) - now())))::int AS s "
            "FROM email_codes WHERE user_id = %s AND purpose = %s",
            (RESEND_COOLDOWN_SECONDS, user_id, purpose))
        if wait and wait["s"] > 0:
            return None, int(wait["s"])
        sends = pool.q1(
            "SELECT count(*) AS n, min(sent_at) AS first FROM email_code_sends "
            "WHERE user_id = %s AND purpose = %s AND sent_at > now() - interval '1 hour'",
            (user_id, purpose))
        if sends["n"] >= HOURLY_SENDS:
            left = pool.q1("SELECT greatest(1, ceil(extract(epoch FROM %s::timestamptz + interval '1 hour' - now())))::int AS s",
                           (sends["first"],))
            return None, int(left["s"])
        code = f"{secrets.randbelow(10 ** 6):06d}"
        pool.exec_(
            "INSERT INTO email_codes (user_id, purpose, code_hash, created_at, expires_at, attempts) "
            "VALUES (%s, %s, %s, now(), now() + make_interval(mins => %s), 0) "
            "ON CONFLICT (user_id, purpose) DO UPDATE SET code_hash = excluded.code_hash, "
            "created_at = excluded.created_at, expires_at = excluded.expires_at, attempts = 0",
            (user_id, purpose, _digest(user_id, purpose, code), CODE_TTL_MINUTES))
        pool.exec_("DELETE FROM email_code_sends WHERE user_id = %s AND sent_at <= now() - interval '1 hour'",
                   (user_id,))
        pool.exec_("INSERT INTO email_code_sends (user_id, purpose) VALUES (%s, %s)", (user_id, purpose))
    return code, 0


def check(user_id: str, purpose: str, code: str) -> bool:
    """True, once, for the live code. A wrong guess uses up one attempt."""
    code = (code or "").strip()
    with pool.transaction():
        row = pool.q1(
            "SELECT code_hash, attempts, expires_at > now() AS live FROM email_codes "
            "WHERE user_id = %s AND purpose = %s FOR UPDATE", (user_id, purpose))
        if not row or not row["live"] or row["attempts"] >= MAX_ATTEMPTS:
            return False
        if re.fullmatch(r"\d{6}", code) and hmac.compare_digest(row["code_hash"], _digest(user_id, purpose, code)):
            pool.exec_("DELETE FROM email_codes WHERE user_id = %s AND purpose = %s", (user_id, purpose))
            return True
        pool.exec_("UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = %s AND purpose = %s",
                   (user_id, purpose))
    return False


def void(user_id: str) -> None:
    """Drop every live code of the account (after a password reset)."""
    pool.exec_("DELETE FROM email_codes WHERE user_id = %s", (user_id,))


_SUBJECTS = {
    "verify": "รหัสยืนยันอีเมล AegisWAF CDN",
    "reset": "รหัสตั้งรหัสผ่านใหม่ AegisWAF CDN",
}
_LEADS = {
    "verify": "ใช้รหัสนี้ยืนยันอีเมลของบัญชี AegisWAF CDN",
    "reset": "มีคำขอตั้งรหัสผ่านใหม่ของบัญชี AegisWAF CDN ที่ใช้อีเมลนี้ ใช้รหัสนี้เพื่อตั้งรหัสผ่านใหม่",
}
_FOOTS = {
    "verify": "ถ้าคุณไม่ได้สมัคร ไม่ต้องทำอะไร บัญชีที่ไม่ได้ยืนยันจะใช้ส่วนที่สำคัญไม่ได้",
    "reset": "ถ้าคุณไม่ได้ขอ ไม่ต้องทำอะไร รหัสผ่านเดิมยังใช้ได้ ตั้งรหัสผ่านใหม่แล้วทุกอุปกรณ์จะออกจากระบบ",
}


def send_code_email(to_addr: str, purpose: str, code: str) -> bool:
    lead, foot = _LEADS[purpose], _FOOTS[purpose]
    text = f"{lead}\n\n    {code}\n\nรหัสใช้ได้ {CODE_TTL_MINUTES} นาที และใช้ได้ครั้งเดียว\n{foot}\n"
    html = (
        '<div style="background:#080c14;padding:32px 16px;font-family:Inter,Segoe UI,Arial,sans-serif">'
        '<div style="max-width:440px;margin:0 auto;background:#101827;border:1px solid #1e293b;border-radius:14px;'
        'padding:28px;color:#f1f5f9">'
        '<div style="font:700 15px Inter,Segoe UI,Arial,sans-serif;letter-spacing:-.01em">'
        '<span style="color:#d0674a">Aegis</span>WAF <span style="color:#a3a3a4">CDN</span></div>'
        '<div style="font:10px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.12em;color:#7d8ba3;'
        'text-transform:uppercase;margin-bottom:22px">Web Application Firewall</div>'
        f'<p style="margin:0 0 18px;color:#94a3b8;font-size:14px;line-height:1.6">{lead}</p>'
        '<div style="font:700 32px ui-monospace,Menlo,Consolas,monospace;letter-spacing:.35em;text-align:center;'
        'padding:16px 0;border:1px solid rgba(243,128,32,.25);background:rgba(243,128,32,.12);border-radius:10px;'
        f'color:#f38020">{code}</div>'
        f'<p style="margin:18px 0 0;color:#7d8ba3;font-size:12.5px;line-height:1.6">รหัสใช้ได้ {CODE_TTL_MINUTES} นาที '
        f'และใช้ได้ครั้งเดียว<br>{foot}</p>'
        '</div></div>'
    )
    return mailer.send_mail(to_addr, _SUBJECTS[purpose], text, html)
