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
import os
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
from ml_policy import ml_access_decision
from email_sender import send_otp_email

logger = logging.getLogger(__name__)
COOKIE_NAME = "waf_otp_clearance"
DEFAULT_PATHS = ["/login*", "/admin*", "/wp-login.php", "/administrator*", "/user/login*"]
DEFAULT_CLEARANCE_TTL = 3600
DEFAULT_CODE_LENGTH = 6
DEFAULT_CODE_TTL = 300
MAX_VERIFY_ATTEMPTS = 5
REQUEST_RATE_LIMIT_PER_10MIN = 3
HMAC_SECRET = (
    os.getenv("OTP_HMAC_SECRET")
    or os.getenv("CAPTCHA_HMAC_SECRET")
    or os.getenv("CONTROL_TOKEN")
    or secrets.token_hex(32)
)


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
    }


def get_config(host: str, client=None) -> tuple[dict, object | None]:
    client = client if client is not None else _redis()
    if client is None:
        return _default_config(host), None
    try:
        raw = client.get(_config_key(host))
        if not raw:
            return _default_config(host), client
        value = json.loads(raw)
        if not isinstance(value, dict):
            return _default_config(host), client
        result = _default_config(host)
        result.update(value)
        return result, client
    except Exception as exc:
        logger.warning("otp config read failed for %s: %s", host, exc)
        return _default_config(host), None


def _matches_path(path: str, patterns: list[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(path, str(pattern)) for pattern in patterns)


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


def _cookie_valid(request: Request, host: str) -> bool:
    jar = SimpleCookie()
    try:
        jar.load(request.headers.get("cookie", ""))
        value = jar[COOKIE_NAME].value
    except (KeyError, ValueError):
        return False
    parts = value.split(".", 2)
    if len(parts) != 3:
        return False
    expiry, cookie_host, signature = parts
    if not expiry.isdigit() or int(expiry) <= int(time.time()):
        return False
    if normalize_host(cookie_host) != host:
        return False
    message = "\x1f".join([subnet_identity(client_ip(request)), user_agent(request), host, expiry])
    expected = hmac.new(
        HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def access_decision(request: Request) -> str:
    original_method = request.headers.get("x-original-method", request.method).upper()
    if original_method not in {"GET", "HEAD"}:
        return "allow"
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    path = urlsplit(request.headers.get("x-original-uri", "/")).path or "/"
    config, client = get_config(host)
    if client is None or not config.get("enabled"):
        return "allow"
    if not _matches_path(path, config.get("login_paths", DEFAULT_PATHS)):
        return "allow"
    if _is_bypassed(client_ip(request), config.get("bypass_ips", [])):
        return "allow"
    return "allow" if _cookie_valid(request, host) else "challenge"


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
    if captcha_access_decision(request) == "challenge":
        return Response(
            status_code=401,
            headers={"X-Shield-Type": "captcha", "Cache-Control": "no-store"},
        )
    if access_decision(request) == "challenge":
        return Response(
            status_code=401,
            headers={"X-Shield-Type": "otp", "Cache-Control": "no-store"},
        )
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
    if ml_decision == "challenge":
        return Response(
            status_code=401,
            headers={"X-Shield-Type": "ml", "Cache-Control": "no-store"},
        )
    return Response(status_code=204)


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
    config, _ = get_config(host, client)
    if not config.get("enabled"):
        return JSONResponse({"success": False, "error": "OTP not enabled for this site"}, status_code=404)

    address = client_ip(request)
    if _request_rate_limited(client, address, payload.email):
        return JSONResponse({"success": False, "error": "too many requests, try again later"}, status_code=429)

    code_length = max(4, min(8, int(config.get("code_length", DEFAULT_CODE_LENGTH))))
    code_ttl = max(60, min(900, int(config.get("code_ttl", DEFAULT_CODE_TTL))))
    code = "".join(secrets.choice("0123456789") for _ in range(code_length))
    challenge_id = str(uuid.uuid4())
    record = {
        "host": host,
        "email": payload.email,
        "code_hash": hashlib.sha256(code.encode()).hexdigest(),
        "attempts": 0,
        "ip_subnet": subnet_identity(address),
        "ua_digest": hashlib.sha256(user_agent(request).encode("utf-8", "ignore")).hexdigest(),
    }
    client.setex(f"waf:otp:challenge:{challenge_id}", code_ttl, json.dumps(record, separators=(",", ":")))

    sent = send_otp_email(payload.email, code)
    if not sent:
        # Fail loud rather than claiming success with nowhere for the code
        # to actually go -- SMTP is not configured on this deployment yet.
        return JSONResponse(
            {"success": False, "error": "could not send verification email -- try again later"},
            status_code=502,
        )
    return JSONResponse({"success": True, "challenge_id": challenge_id})


async def verify_code(request: Request, payload: OtpVerifyPayload) -> Response:
    client = _redis()
    if client is None:
        return JSONResponse({"success": False, "error": "verification unavailable"}, status_code=503)

    host = normalize_host(payload.host)
    address = client_ip(request)
    key = f"waf:otp:challenge:{payload.challenge_id}"

    try:
        raw = client.get(key)
        if not raw:
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
        return JSONResponse({"success": False, "error": "verification context mismatch"}, status_code=400)

    attempts = int(record.get("attempts", 0)) + 1
    if attempts > MAX_VERIFY_ATTEMPTS:
        client.delete(key)
        return JSONResponse({"success": False, "error": "too many attempts, request a new code"}, status_code=429)

    submitted_hash = hashlib.sha256(re.sub(r"\s+", "", payload.code).encode()).hexdigest()
    if not hmac.compare_digest(submitted_hash, str(record.get("code_hash", ""))):
        record["attempts"] = attempts
        ttl = client.ttl(key)
        client.setex(key, max(1, ttl), json.dumps(record, separators=(",", ":")))
        return JSONResponse({"success": False, "error": "incorrect code"}, status_code=400)

    client.delete(key)
    config, _ = get_config(host, client)
    ttl = max(900, min(43200, int(config.get("clearance_ttl", DEFAULT_CLEARANCE_TTL))))
    expiry = int(time.time()) + ttl
    message = "\x1f".join([subnet_identity(address), user_agent(request), host, str(expiry)])
    signature = hmac.new(HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    response = JSONResponse({"success": True})
    response.set_cookie(
        COOKIE_NAME, f"{expiry}.{host}.{signature}", max_age=ttl, expires=expiry,
        path="/", secure=True, httponly=True, samesite="lax",
    )
    return response


def _challenge_html() -> str:
    return """<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify it's you</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e5e7eb;font:16px system-ui,sans-serif}
main{width:min(92vw,380px);padding:32px;border:1px solid #263248;border-radius:16px;background:#111a2b;box-shadow:0 18px 50px #0006}
h1{font-size:19px;margin:0 0 6px}p{color:#94a3b8;margin:0 0 18px;font-size:14px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #334155;background:#0b1220;color:#e5e7eb;font-size:15px;margin-bottom:10px}
button{width:100%;padding:10px;border-radius:8px;border:0;background:#fb923c;color:#111;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
#error{color:#fca5a5;min-height:1.3em;font-size:13px;margin-top:8px}
#code-step{display:none}
</style></head><body><main>
<div id="email-step">
<h1>ยืนยันตัวตนด้วยอีเมล</h1><p>กรอกอีเมลของคุณ เราจะส่งรหัสยืนยันไปให้</p>
<input id="email" type="email" placeholder="you@example.com" autocomplete="email">
<button id="send-btn">ส่งรหัสยืนยัน</button>
</div>
<div id="code-step">
<h1>กรอกรหัสยืนยัน</h1><p id="sent-to"></p>
<input id="code" type="text" inputmode="numeric" placeholder="000000" autocomplete="one-time-code">
<button id="verify-btn">ยืนยัน</button>
</div>
<p id="error"></p>
</main><script>
let challengeId=null;
const emailStep=document.getElementById('email-step'),codeStep=document.getElementById('code-step'),
      errorEl=document.getElementById('error'),sendBtn=document.getElementById('send-btn'),
      verifyBtn=document.getElementById('verify-btn');
sendBtn.onclick=async()=>{
  const email=document.getElementById('email').value.trim();
  if(!email){errorEl.textContent='กรุณากรอกอีเมล';return;}
  sendBtn.disabled=true;errorEl.textContent='';
  try{
    const r=await fetch('/cdn-cgi/otp/request',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({host:location.host,email:email})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok||!j.success){errorEl.textContent=j.error||'ส่งรหัสไม่สำเร็จ';sendBtn.disabled=false;return;}
    challengeId=j.challenge_id;
    document.getElementById('sent-to').textContent='ส่งรหัสไปที่ '+email+' แล้ว';
    emailStep.style.display='none';codeStep.style.display='block';
  }catch(e){errorEl.textContent='เกิดข้อผิดพลาด กรุณาลองใหม่';sendBtn.disabled=false;}
};
verifyBtn.onclick=async()=>{
  const code=document.getElementById('code').value.trim();
  if(!code||!challengeId)return;
  verifyBtn.disabled=true;errorEl.textContent='';
  try{
    const r=await fetch('/cdn-cgi/otp/verify',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({challenge_id:challengeId,code:code,host:location.host})});
    const j=await r.json().catch(()=>({}));
    if(r.ok&&j.success){location.reload();return;}
    errorEl.textContent=j.error||'รหัสไม่ถูกต้อง';verifyBtn.disabled=false;
  }catch(e){errorEl.textContent='เกิดข้อผิดพลาด กรุณาลองใหม่';verifyBtn.disabled=false;}
};
</script></body></html>"""


async def issue_challenge_page(request: Request) -> Response:
    host = normalize_host(request.headers.get("host", ""))
    config, client = get_config(host)
    if client is None:
        return Response(status_code=503, content="OTP service temporarily unavailable")
    if not config.get("enabled"):
        return Response(status_code=404, content="Not found")
    return HTMLResponse(_challenge_html(), headers={"Cache-Control": "no-store, no-cache", "Pragma": "no-cache"})
