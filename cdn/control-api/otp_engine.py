"""OTP Shield -- opt-in edge gate in front of an origin's login page.

Sibling of captcha_engine.py, same shape throughout (Redis-backed per-domain
config, HMAC-signed clearance cookie, auth_request-style access check +
challenge page). The difference: instead of proving "not a simple bot" via a
PoW puzzle, the visitor proves they control a real inbox. This is NOT
per-account authentication -- the WAF has no visibility into the origin's
own user database (Zero-Touch Origin Principle), so this only establishes
"a human reachable at this address requested access", the same trust level
class as the existing CAPTCHA gate, just via a different proof.

Uses a distinct cookie name (waf_otp_clearance) so it can be enabled
alongside CAPTCHA on the same origin independently -- solving one does not
clear the other. Both gates share HTTP 401 as their nginx auth_request
failure status (see shield_access below for why: nginx's auth_request
module only recognizes 401/403 as valid deny statuses eligible for
error_page mapping, an earlier attempt at a distinct 418 for OTP made nginx
log "auth request unexpected status" and 500 instead of redirecting) and
are told apart via an X-Shield-Type response header nginx forwards to a
single challenge-page route.
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import time
import uuid
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, EmailStr, Field

from captcha_engine import _redis, normalize_host, client_ip, subnet_identity, user_agent
from captcha_engine import access_decision as captcha_access_decision
from captcha_engine import _new_challenge
from captcha_engine import _challenge_html as _captcha_challenge_html
from captcha_engine import (
    has_clearance, last_known_config, max_cookie_expiry, owned_config, remember_config, required_secret,
)
from ml_policy import ml_access_decision
from email_sender import send_otp_email
from captcha_engine import get_config as captcha_get_config
from shield_paths import is_protected
import rate_limit
import shield_events

logger = logging.getLogger(__name__)
COOKIE_NAME = "waf_otp_clearance"
DEFAULT_PATHS = ["/login*", "/admin*", "/wp-login.php", "/administrator*", "/user/login*"]
DEFAULT_CLEARANCE_TTL = 3600
DEFAULT_CODE_LENGTH = 6
DEFAULT_CODE_TTL = 300
# Admin-adjustable ranges (seconds). A clearance longer than 12 h is meant for
# allowlist mode, where removing someone still revokes them immediately.
CODE_TTL_RANGE = (60, 1800)
CLEARANCE_TTL_RANGE = (900, 30 * 86400)
MAX_VERIFY_ATTEMPTS = 5
REQUEST_RATE_LIMIT_PER_10MIN = 3
HMAC_SECRET = required_secret("OTP_HMAC_SECRET")


class OtpRequestPayload(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    email: EmailStr


class OtpVerifyPayload(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=4, max_length=8)
    host: str = Field(min_length=1, max_length=253)


def _config_key(host: str) -> str:
    return f"waf:otp:domain:{normalize_host(host)}"


def _default_config(host: str = "") -> dict:
    return {
        "origin_id": "",
        "domain": normalize_host(host),
        "enabled": False,
        "login_paths": list(DEFAULT_PATHS),
        "clearance_ttl": DEFAULT_CLEARANCE_TTL,
        "bypass_ips": [],
        "code_length": DEFAULT_CODE_LENGTH,
        "code_ttl": DEFAULT_CODE_TTL,
        "channel": "email",
        "mode": "enforce",          # or "log_only" -- see captcha_engine._default_config
        "exclude_paths": [],
        # "open": any inbox that can receive the code passes (bot friction).
        # "allowlist": only allowed_emails -- exact addresses or "@domain.com".
        "access_mode": "open",
        "allowed_emails": [],
    }


def email_allowed(config: dict, email: str) -> bool:
    if config.get("access_mode") != "allowlist":
        return True
    email = (email or "").strip().lower()
    if "@" not in email:
        return False
    for entry in config.get("allowed_emails") or []:
        entry = str(entry).strip().lower()
        if not entry:
            continue
        if entry.startswith("@") and email.endswith(entry):
            return True
        if entry == email:
            return True
    return False


def _session_key(sid: str) -> str:
    return f"waf:otp:session:{sid}"


def get_config(host: str, client=None) -> tuple[dict, object | None]:
    # Same ownership check and last-known fallback as captcha_engine.get_config.
    host = normalize_host(host)
    client = client if client is not None else _redis()
    if client is None:
        return last_known_config("otp", host, _default_config(host)), None
    try:
        raw = client.get(_config_key(host))
        value = json.loads(raw) if raw else None
        result = owned_config(client, host, value, _default_config(host))
    except Exception as exc:
        logger.warning("otp config read failed for %s: %s", host, exc)
        return last_known_config("otp", host, _default_config(host)), None
    remember_config("otp", host, result)
    return result, client


def _is_bypassed(address: str, bypass_ips: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for item in bypass_ips or []:
        try:
            if ip in ipaddress.ip_network(str(item), strict=False):
                return True
        except ValueError:
            continue
    return False


def _cookie_valid(request: Request, host: str, config: dict | None = None, client=None) -> bool:
    jar = SimpleCookie()
    try:
        jar.load(request.headers.get("cookie", ""))
        value = jar[COOKIE_NAME].value
    except (KeyError, ValueError):
        return False
    # "<expiry>.<host>.<signature>": the host itself contains dots, so split
    # the expiry off the front and the (hex, dot-free) signature off the end.
    # split(".", 2) cut the host at its first dot, so no clearance cookie for a
    # real hostname ever validated and every visitor looped back to the
    # challenge right after passing it (seen in production 2026-09-29).
    # "<expiry>.<host>.<session id>.<signature>" -- host has dots, the other
    # three parts never do.
    expiry, _, rest = value.partition(".")
    rest, _, signature = rest.rpartition(".")
    cookie_host, _, sid = rest.rpartition(".")
    if not cookie_host or not sid or not signature:
        return False
    if not expiry.isdigit() or int(expiry) <= int(time.time()):
        return False
    # N6: never longer than the configured clearance, whatever the cookie says.
    if int(expiry) > max_cookie_expiry(config or _default_config(host), CLEARANCE_TTL_RANGE):
        return False
    if normalize_host(cookie_host) != host:
        return False
    message = "\x1f".join([subnet_identity(client_ip(request)), user_agent(request), host, expiry, sid])
    expected = hmac.new(
        HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    if (config or {}).get("access_mode") == "allowlist":
        # Re-check the verified email against the *current* list on every
        # request, so removing someone takes effect immediately instead of
        # when their cookie expires.
        try:
            raw = client.get(_session_key(sid)) if client is not None else None
            session = json.loads(raw) if raw else None
        except Exception:
            return False
        if not session or session.get("host") != host:
            return False
        return email_allowed(config, session.get("email", ""))
    return True


def access_decision(request: Request) -> str:
    # All methods except OPTIONS -- see captcha_engine.access_decision.
    original_method = request.headers.get("x-original-method", request.method).upper()
    if original_method == "OPTIONS":
        return "allow"
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    config, client = get_config(host)
    if not config.get("enabled"):
        return "allow"
    if not is_protected(request.headers.get("x-original-uri", "/"),
                        config.get("login_paths", DEFAULT_PATHS), config.get("exclude_paths")):
        return "allow"
    if _is_bypassed(client_ip(request), config.get("bypass_ips", [])):
        return "allow"
    if _cookie_valid(request, host, config, client):
        return "allow"
    if client is None:
        # H83, see captcha_engine.access_decision.
        return "allow" if config.get("mode") == "log_only" else "unavailable"
    return "challenge"


async def otp_access(request: Request) -> Response:
    # Kept for direct/standalone use (not wired into nginx -- see
    # shield_access below for why). 418 here documents the original intent:
    # distinct from captcha's 401 so a shared error_page wouldn't collide.
    if access_decision(request) == "challenge":
        return Response(
            status_code=418,
            headers={"X-Otp-Required": "1", "Cache-Control": "no-store"},
        )
    return Response(status_code=204)


def _deny(request: Request, kind: str) -> Response | None:
    """GET/HEAD without clearance -> 401, which nginx turns into the challenge
    page. Any other method -> 403: a form or API POST can't be answered with an
    HTML page it will never render, and the request must not reach the origin.
    nginx serves its normal 403 page for it (same path as a ModSecurity block).

    In log_only mode the event is recorded as what *would* have happened and
    None is returned: the request goes through (and the next gate is still
    checked)."""
    method = request.headers.get("x-original-method", request.method).upper()
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    path = urlsplit(request.headers.get("x-original-uri", "/")).path or "/"
    config, client = (captcha_get_config if kind == "captcha" else get_config)(host)
    blocked = method not in {"GET", "HEAD"}
    log_only = config.get("mode") == "log_only"
    event = "blocked_no_clearance" if blocked else "challenge_shown"
    if log_only:
        event = "would_block" if blocked else "would_challenge"
    shield_events.record(
        client, kind=kind, event=event,
        host=host, origin_id=config.get("origin_id", ""), client_ip=client_ip(request), path=path,
    )
    if log_only:
        return None
    if blocked:
        return Response(
            status_code=403,
            headers={"X-Shield-Type": f"{kind}-required", "Cache-Control": "no-store"},
        )
    return Response(
        status_code=401,
        headers={"X-Shield-Type": kind, "Cache-Control": "no-store"},
    )


async def shield_access(request: Request) -> Response:
    # Combined captcha+OTP gate for nginx's auth_request.
    #
    # nginx's ngx_http_auth_request_module only treats 401 and 403 as
    # meaningful "auth failed" statuses eligible for error_page mapping --
    # any other code (we tried 418) makes it log "auth request unexpected
    # status" and return 500 to the client instead. 403 is ModSecurity's own
    # block status on this stack, so it's not available either (a shared
    # error_page 403 would rewrite real WAF blocks into a challenge page).
    # That leaves exactly one usable code: 401. Both gates share it, and
    # nginx (which can't inspect the body) can't tell them apart from the
    # status alone -- so this endpoint decides FOR nginx, tags the reason on
    # a response header (X-Shield-Type), and nginx forwards that header
    # (via auth_request_set + proxy_set_header) to the single challenge-page
    # route, which reads it and renders the right page.
    #
    # P2.6: the request rate limit comes first (see rate_limit.py for why it
    # lives here). Over the limit -> 401 tagged "ratelimit", which the
    # challenge route turns into a 429 with Retry-After.
    allowed, retry_after = rate_limit.check(
        _redis(), request.headers.get("x-original-method", request.method),
        request.headers.get("x-original-uri", "/"), client_ip(request),
    )
    if not allowed:
        return Response(
            status_code=401,
            headers={"X-Shield-Type": "ratelimit", "Retry-After": str(retry_after), "Cache-Control": "no-store"},
        )
    protected = False
    for kind, decide in (("captcha", captcha_access_decision), ("otp", access_decision)):
        decision = decide(request)
        if decision == "unavailable":
            # H83: an enforcing gate whose Redis is down -> 503 page, not the site.
            return Response(
                status_code=401,
                headers={"X-Shield-Type": "unavailable", "Cache-Control": "no-store"},
            )
        if decision == "challenge":
            denied = _deny(request, kind)
            if denied is not None:
                return denied
        if decision != "allow" or _protects(request, kind):
            protected = True
    # Gen3 roadmap 1.3: third branch, ML-driven. No-op ("pass" always,
    # immediately, no HTTP call) unless a human has enabled enforcement in
    # Settings -- see ml_policy.py's module docstring. "block" reuses 403,
    # which already falls straight through to the existing static
    # /403.html at the nginx layer (no route needed here). "challenge"
    # reuses the same native PoW form as captcha (roadmap's own spec: "ส่ง
    # เข้า Native Proof-of-Work Challenge") via issue_ml_challenge() below --
    # NOT captcha_engine.issue_challenge() directly, because that function
    # 404s unless *that origin's own* CAPTCHA toggle is enabled, and ML
    # enforcement is a global policy independent of any origin's captcha
    # opt-in (see main.py's /cdn-cgi/challenge dispatch).
    ml_decision = await ml_access_decision(request)
    if ml_decision == "block":
        return Response(
            status_code=403,
            headers={"X-Shield-Type": "ml-block", "Cache-Control": "no-store"},
        )
    # H10: a visitor who already solved the challenge (waf_clearance) is not
    # sent back to it on every flagged request.
    if ml_decision == "challenge" and not has_clearance(request):
        return Response(
            status_code=401,
            headers={"X-Shield-Type": "ml", "Cache-Control": "no-store"},
        )
    # P2.3: the response to a path a gate protects is never stored by the
    # edge or any shared cache; nginx turns this header into
    # Cache-Control: private, no-store.
    return Response(status_code=204, headers={"X-Shield-Protected": "1"} if protected else {})


def _protects(request: Request, kind: str) -> bool:
    """Whether the gate covers this request's path (enabled and matching),
    whether or not this visitor has passed it."""
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    config, _ = (captcha_get_config if kind == "captcha" else get_config)(host)
    if not config.get("enabled") or (kind == "captcha" and config.get("engine", "native") != "native"):
        return False
    return is_protected(request.headers.get("x-original-uri", "/"),
                        config.get("login_paths", DEFAULT_PATHS), config.get("exclude_paths"))


async def issue_ml_challenge(request: Request) -> Response:
    """Same PoW form as captcha_engine.issue_challenge(), minus its
    per-origin `config.get("enabled")` gate -- ML enforcement is a global
    settings flag, not an origin-level opt-in, so an origin with CAPTCHA off
    must still be able to reach this page when ML flags a request. Solving
    it sets the same waf_clearance cookie via the existing, unmodified
    captcha_engine.verify_challenge() (POST /cdn-cgi/challenge/verify),
    which never gated on config.enabled in the first place -- only issuance
    did, so that's the only piece this function needs to reimplement.
    """
    client = _redis()
    if client is None:
        return Response(status_code=503, content="Challenge service temporarily unavailable")
    try:
        return HTMLResponse(
            _captcha_challenge_html(_new_challenge(request, {"pow_difficulty": 3}, client)),
            headers={"Cache-Control": "no-store, no-cache", "Pragma": "no-cache"},
        )
    except Exception:
        logger.exception("ml challenge issuance failed")
        return Response(status_code=503, content="Challenge service temporarily unavailable")


def _request_rate_limited(client, address: str, email: str) -> bool:
    try:
        key = f"waf:otp:request-rate:{address}:{hashlib.sha256(email.encode()).hexdigest()[:16]}"
        count = int(client.incr(key))
        if count == 1:
            client.expire(key, 600)
        return count > REQUEST_RATE_LIMIT_PER_10MIN
    except Exception:
        return True


async def request_code(request: Request, payload: OtpRequestPayload) -> Response:
    client = _redis()
    if client is None:
        return JSONResponse({"success": False, "error": "OTP service unavailable"}, status_code=503)

    host = normalize_host(payload.host)
    # Same binding as captcha verify: the body may only name the site the
    # request arrived on, so one site's page cannot drive another site's OTP
    # (and its allowlist mail) (re-audit 2026-10-17).
    if not host or host != normalize_host(request.headers.get("host", "")):
        return JSONResponse({"success": False, "error": "host mismatch"}, status_code=400)
    config, _ = get_config(host, client)
    if not config.get("enabled"):
        return JSONResponse({"success": False, "error": "OTP not enabled for this site"}, status_code=404)

    address = client_ip(request)

    def event(name: str) -> None:
        shield_events.record(client, kind="otp", event=name, host=host,
                             origin_id=config.get("origin_id", ""), client_ip=address, email=payload.email)

    if _request_rate_limited(client, address, payload.email):
        event("otp_rate_limited")
        return JSONResponse({"success": False, "error": "too many requests, try again later"}, status_code=429)

    # Not on the list: behave exactly as if a code was sent (same response,
    # a stored challenge that can never verify) so the page can't be used to
    # find out which addresses have access. No email goes out.
    allowed = email_allowed(config, payload.email)

    code_length = max(4, min(8, int(config.get("code_length", DEFAULT_CODE_LENGTH))))
    code_ttl = max(CODE_TTL_RANGE[0], min(CODE_TTL_RANGE[1], int(config.get("code_ttl", DEFAULT_CODE_TTL))))
    code = "".join(secrets.choice("0123456789") for _ in range(code_length))
    challenge_id = str(uuid.uuid4())
    record = {
        "host": host,
        "email": payload.email,
        # never matches any submitted code when the address isn't allowed
        "code_hash": hashlib.sha256(code.encode()).hexdigest() if allowed else secrets.token_hex(32),
        "attempts": 0,
        "ip_subnet": subnet_identity(address),
        "ua_digest": hashlib.sha256(user_agent(request).encode("utf-8", "ignore")).hexdigest(),
    }
    client.setex(f"waf:otp:challenge:{challenge_id}", code_ttl, json.dumps(record, separators=(",", ":")))

    if not allowed:
        event("otp_not_allowed")
        return JSONResponse({"success": True, "challenge_id": challenge_id})

    sent = send_otp_email(payload.email, code, code_ttl)
    if not sent:
        event("otp_send_failed")
        # Fail loud rather than claiming success with nowhere for the code
        # to actually go -- SMTP is not configured on this deployment yet.
        return JSONResponse(
            {"success": False, "error": "could not send verification email -- try again later"},
            status_code=502,
        )
    event("otp_requested")
    return JSONResponse({"success": True, "challenge_id": challenge_id})


async def verify_code(request: Request, payload: OtpVerifyPayload) -> Response:
    client = _redis()
    if client is None:
        return JSONResponse({"success": False, "error": "verification unavailable"}, status_code=503)

    host = normalize_host(payload.host)
    if not host or host != normalize_host(request.headers.get("host", "")):
        return JSONResponse({"success": False, "error": "host mismatch"}, status_code=400)
    address = client_ip(request)
    key = f"waf:otp:challenge:{payload.challenge_id}"
    config, _ = get_config(host, client)
    record: dict = {}

    def event(name: str) -> None:
        # The email comes from the stored challenge, never from this request.
        shield_events.record(client, kind="otp", event=name, host=host,
                             origin_id=config.get("origin_id", ""), client_ip=address,
                             email=str(record.get("email", "")))

    try:
        raw = client.get(key)
        if not raw:
            event("otp_expired")
            return JSONResponse({"success": False, "error": "code expired"}, status_code=400)
        record = json.loads(raw)
    except Exception as exc:
        logger.warning("otp challenge lookup failed: %s", exc)
        return JSONResponse({"success": False, "error": "verification unavailable"}, status_code=503)

    if (
        record.get("host") != host
        or record.get("ip_subnet") != subnet_identity(address)
        or record.get("ua_digest") != hashlib.sha256(user_agent(request).encode("utf-8", "ignore")).hexdigest()
    ):
        event("otp_context_mismatch")
        return JSONResponse({"success": False, "error": "verification context mismatch"}, status_code=400)

    attempts = int(record.get("attempts", 0)) + 1
    if attempts > MAX_VERIFY_ATTEMPTS:
        client.delete(key)
        event("otp_too_many_attempts")
        return JSONResponse({"success": False, "error": "too many attempts, request a new code"}, status_code=429)

    submitted_hash = hashlib.sha256(re.sub(r"\s+", "", payload.code).encode()).hexdigest()
    if not hmac.compare_digest(submitted_hash, str(record.get("code_hash", ""))):
        record["attempts"] = attempts
        ttl = client.ttl(key)
        client.setex(key, max(1, ttl), json.dumps(record, separators=(",", ":")))
        event("otp_wrong_code")
        return JSONResponse({"success": False, "error": "incorrect code"}, status_code=400)

    client.delete(key)
    event("otp_verified")
    ttl = max(CLEARANCE_TTL_RANGE[0], min(CLEARANCE_TTL_RANGE[1], int(config.get("clearance_ttl", DEFAULT_CLEARANCE_TTL))))
    expiry = int(time.time()) + ttl
    sid = secrets.token_hex(16)
    client.setex(_session_key(sid), ttl, json.dumps({"email": record.get("email", ""), "host": host},
                                                    separators=(",", ":")))
    message = "\x1f".join([subnet_identity(address), user_agent(request), host, str(expiry), sid])
    signature = hmac.new(HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    response = JSONResponse({"success": True})
    response.set_cookie(
        COOKIE_NAME, f"{expiry}.{host}.{sid}.{signature}", max_age=ttl, expires=expiry,
        path="/", secure=True, httponly=True, samesite="lax",
    )
    return response


def _challenge_html(allowlist: bool = False, code_length: int = DEFAULT_CODE_LENGTH) -> str:
    """The OTP Shield page visitors of a protected site see before its login
    path. Self-contained (no external fonts or scripts) and styled like the
    dashboard: dark by default, light when the visitor's system is light."""
    sent_prefix = "หากอีเมลนี้มีสิทธิ์เข้าใช้ เราได้ส่งรหัสไปที่ " if allowlist else "ส่งรหัสไปที่ "
    code_length = max(4, min(8, int(code_length)))
    boxes = "".join(
        '<input class="digit" inputmode="numeric" maxlength="%d" aria-label="รหัสหลักที่ %d" autocomplete="%s">'
        % ((code_length, i + 1, "one-time-code") if i == 0 else (1, i + 1, "off"))
        for i in range(code_length)
    )
    return """<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Verify it's you</title>
<style>
:root{--bg:#080c14;--surface:#101827;--field:#0b111e;--border:#1e293b;--border-hi:#334155;--text:#f1f5f9;--muted:#94a3b8;--dim:#7d8ba3;
--accent:#f38020;--accent-hi:#ea580c;--accent-soft:rgba(243,128,32,.12);--accent-line:rgba(243,128,32,.28);--danger:#f87171;--danger-soft:rgba(239,68,68,.12)}
@media (prefers-color-scheme:light){:root{--bg:#f1f5f9;--surface:#fff;--field:#f8fafc;--border:#e2e8f0;--border-hi:#cbd5e1;--text:#0f172a;--muted:#475569;--dim:#5b6b82;
--accent:#ea580c;--accent-hi:#c2410c;--accent-soft:rgba(234,88,12,.08);--accent-line:rgba(234,88,12,.25);--danger:#dc2626;--danger-soft:rgba(220,38,38,.08)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px 16px;
background:radial-gradient(900px 380px at 50% -120px,var(--accent-soft),transparent 70%),var(--bg);color:var(--text);
font:14px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans Thai",Tahoma,sans-serif;-webkit-font-smoothing:antialiased}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px 24px;
box-shadow:0 1px 3px rgba(0,0,0,.12),0 24px 60px -24px rgba(0,0,0,.55)}
.brand{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:24px}
.brand-l{display:flex;align-items:center;gap:10px;min-width:0}
.tile{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:var(--accent-soft);border:1px solid var(--accent-line);color:var(--accent);flex:none}
.name{font-weight:700;font-size:13px;letter-spacing:-.01em}.sub{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.host{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:3px 9px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.steps{display:flex;gap:6px;margin-bottom:18px}.steps i{height:3px;flex:1;border-radius:3px;background:var(--border)}.steps i.on{background:var(--accent)}
h1{font-size:19px;line-height:1.3;margin:0 0 6px;letter-spacing:-.01em}
p.lead{color:var(--muted);margin:0 0 20px;font-size:13px}
label{display:block;font-size:11.5px;font-weight:600;color:var(--muted);margin-bottom:6px}
.field{position:relative}.field svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--dim)}
input#email{width:100%;padding:10px 12px 10px 36px;border-radius:8px;border:1px solid var(--border);background:var(--field);color:var(--text);font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}
input#email:focus,.digit:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.otp{display:flex;justify-content:center;gap:8px;margin:4px 0 2px}
.digit{width:44px;height:52px;text-align:center;font:700 22px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;border-radius:9px;border:1px solid var(--border);
background:var(--field);color:var(--text);outline:none;caret-color:var(--accent);transition:border-color .15s,box-shadow .15s,background .15s;padding:0}
.digit.filled{border-color:var(--accent-line);background:var(--accent-soft)}
.otp.bad .digit{border-color:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}.otp.bad{animation:shake .35s}
@keyframes shake{20%,60%{transform:translateX(-5px)}40%,80%{transform:translateX(5px)}}
@media (max-width:380px){.otp{gap:5px}.digit{width:38px;height:48px;font-size:20px}}
button.primary{width:100%;margin-top:16px;padding:11px;border-radius:8px;border:0;background:var(--accent);color:#fff;font:600 14px inherit;font-family:inherit;cursor:pointer;
display:flex;align-items:center;justify-content:center;gap:8px;transition:background .15s}
button.primary:hover{background:var(--accent-hi)}button:disabled{opacity:.55;cursor:not-allowed}
.spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.45);border-top-color:#fff;border-radius:50%;animation:r .8s linear infinite;display:none}
button.busy .spin{display:inline-block}@keyframes r{to{transform:rotate(360deg)}}
.row{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:14px;font-size:12px;color:var(--dim)}
.link{background:none;border:0;padding:0;color:var(--accent);font:600 12px inherit;font-family:inherit;cursor:pointer}.link:disabled{color:var(--dim)}
.link:not(:disabled):hover{text-decoration:underline;text-underline-offset:3px}
#error{min-height:18px;margin:12px 0 0;font-size:12.5px;color:var(--danger);text-align:center}
#code-step{display:none}
footer{margin-top:18px;font-size:11px;color:var(--dim);text-align:center;max-width:400px}
</style></head><body><main>
<div class="brand"><div class="brand-l"><div class="tile"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></div>
<div><div class="name mono">Firewall WAF</div><div class="sub mono">Protected site</div></div></div><div class="host mono" id="host"></div></div>
<div class="steps" aria-hidden="true"><i class="on"></i><i id="step2"></i></div>
<div id="email-step">
<h1>ยืนยันตัวตนด้วยอีเมล</h1><p class="lead">เว็บนี้ขอยืนยันอีเมลก่อนเข้าหน้าเข้าสู่ระบบ กรอกอีเมลของคุณ เราจะส่งรหัสยืนยันไปให้</p>
<label for="email">อีเมล</label>
<div class="field"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/></svg>
<input id="email" type="email" placeholder="you@example.com" autocomplete="email"></div>
<button class="primary" id="send-btn"><span class="spin"></span><span>ส่งรหัสยืนยัน</span></button>
</div>
<div id="code-step">
<h1>กรอกรหัสยืนยัน</h1><p class="lead" id="sent-to"></p>
<div class="otp" id="otp">""" + boxes + """</div><input type="hidden" id="code">
<button class="primary" id="verify-btn"><span class="spin"></span><span>ยืนยัน</span></button>
<div class="row"><button class="link" id="change-btn" type="button">เปลี่ยนอีเมล</button><button class="link" id="resend-btn" type="button">ส่งรหัสใหม่</button></div>
</div>
<p id="error" role="alert"></p>
</main><footer>ป้องกันโดย Firewall WAF · รหัสส่งไปที่อีเมลของคุณเท่านั้น ไม่มีใครขอรหัสนี้ทางโทรศัพท์หรือแชต</footer>
<script>
const SENT_PREFIX=""" + json.dumps(sent_prefix, ensure_ascii=False) + """,LEN=""" + str(code_length) + """;
let challengeId=null,email='',wait=0,timer=null;
const $=id=>document.getElementById(id),emailStep=$('email-step'),codeStep=$('code-step'),errorEl=$('error'),
      sendBtn=$('send-btn'),verifyBtn=$('verify-btn'),resendBtn=$('resend-btn'),otp=$('otp'),digits=[...otp.querySelectorAll('.digit')];
$('host').textContent=location.host;
function busy(b,on){b.disabled=on;b.classList.toggle('busy',on);}
function code(){return digits.map(d=>d.value).join('');}
function paint(){digits.forEach(d=>d.classList.toggle('filled',!!d.value));$('code').value=code();}
function fill(s,from){s=s.replace(/\\D/g,'');for(let i=0;i<s.length&&from+i<LEN;i++)digits[from+i].value=s[i];paint();
  const n=Math.min(LEN-1,from+s.length);digits[n].focus();if(code().length===LEN)verify();}
digits.forEach((d,i)=>{
  d.addEventListener('input',()=>{const v=d.value.replace(/\\D/g,'');d.value='';if(v)fill(v,i);else paint();});
  d.addEventListener('keydown',e=>{if(e.key==='Backspace'&&!d.value&&i>0){digits[i-1].value='';digits[i-1].focus();paint();e.preventDefault();}
    else if(e.key==='ArrowLeft'&&i>0)digits[i-1].focus();else if(e.key==='ArrowRight'&&i<LEN-1)digits[i+1].focus();else if(e.key==='Enter')verify();});
  d.addEventListener('focus',()=>d.select());
});
otp.addEventListener('paste',e=>{e.preventDefault();digits.forEach(x=>x.value='');fill((e.clipboardData||window.clipboardData).getData('text'),0);});
function tick(){resendBtn.disabled=wait>0;resendBtn.textContent=wait>0?'ส่งใหม่ได้ใน '+wait+' วิ':'ส่งรหัสใหม่';if(wait>0){wait--;timer=setTimeout(tick,1000);}}
function bad(msg){errorEl.textContent=msg;otp.classList.remove('bad');void otp.offsetWidth;otp.classList.add('bad');}
async function request(btn){
  errorEl.textContent='';busy(btn,true);
  try{
    const r=await fetch('/cdn-cgi/otp/request',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({host:location.host,email:email})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok||!j.success){errorEl.textContent=r.status===429?'ขอรหัสถี่เกินไป รอสักครู่แล้วลองใหม่':r.status===502?'ส่งอีเมลไม่สำเร็จ ลองใหม่ภายหลัง':'ส่งรหัสไม่สำเร็จ';return;}
    challengeId=j.challenge_id;$('sent-to').textContent=SENT_PREFIX+email+' แล้ว';
    emailStep.style.display='none';codeStep.style.display='block';$('step2').className='on';
    digits.forEach(x=>x.value='');paint();digits[0].focus();clearTimeout(timer);wait=60;tick();
  }catch(e){errorEl.textContent='เกิดข้อผิดพลาด กรุณาลองใหม่';}finally{busy(btn,false);if(btn===resendBtn)tick();}
}
sendBtn.onclick=()=>{email=$('email').value.trim();if(!/^[^@\\s]+@[^@\\s]+$/.test(email)){errorEl.textContent='กรุณากรอกอีเมลให้ถูกต้อง';return;}request(sendBtn);};
$('email').addEventListener('keydown',e=>{if(e.key==='Enter')sendBtn.click();});
resendBtn.onclick=()=>request(resendBtn);
$('change-btn').onclick=()=>{codeStep.style.display='none';emailStep.style.display='block';$('step2').className='';errorEl.textContent='';$('email').focus();};
async function verify(){
  const c=code();if(c.length!==LEN||!challengeId||verifyBtn.disabled)return;
  errorEl.textContent='';busy(verifyBtn,true);
  try{
    const r=await fetch('/cdn-cgi/otp/verify',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({challenge_id:challengeId,code:c,host:location.host})});
    const j=await r.json().catch(()=>({}));
    if(r.ok&&j.success){verifyBtn.querySelector('span:last-child').textContent='ยืนยันแล้ว กำลังเข้าเว็บ...';location.reload();return;}
    bad(r.status===429?'ใส่รหัสผิดหลายครั้ง กดส่งรหัสใหม่':'รหัสไม่ถูกต้องหรือหมดอายุ');digits.forEach(x=>x.value='');paint();digits[0].focus();
  }catch(e){errorEl.textContent='เกิดข้อผิดพลาด กรุณาลองใหม่';}
  busy(verifyBtn,false);
}
verifyBtn.onclick=verify;
$('email').focus();
</script></body></html>"""


async def issue_challenge_page(request: Request) -> Response:
    host = normalize_host(request.headers.get("host", ""))
    config, client = get_config(host)
    if client is None:
        return Response(status_code=503, content="OTP service temporarily unavailable")
    if not config.get("enabled"):
        return Response(status_code=404, content="Not found")
    return HTMLResponse(_challenge_html(config.get("access_mode") == "allowlist",
                                        int(config.get("code_length", DEFAULT_CODE_LENGTH))), headers={"Cache-Control": "no-store, no-cache", "Pragma": "no-cache"})
