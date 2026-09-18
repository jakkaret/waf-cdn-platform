import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time
import uuid
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

import redis
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
COOKIE_NAME = "waf_clearance"
DEFAULT_PATHS = ["/login*", "/admin*", "/wp-login.php", "/administrator*", "/user/login*"]
CHALLENGE_TTL = 60
DEFAULT_CLEARANCE_TTL = 3600
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
HMAC_SECRET = os.getenv("CAPTCHA_HMAC_SECRET") or os.getenv("CONTROL_TOKEN") or secrets.token_hex(32)
_redis_client = None


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    nonce: int = Field(ge=0, le=2_000_000)
    host: str = Field(min_length=1, max_length=253)


def _redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            REDIS_URL, decode_responses=True, socket_connect_timeout=1, socket_timeout=1
        )
    try:
        _redis_client.ping()
        return _redis_client
    except Exception as exc:
        logger.warning("captcha redis unavailable: %s", exc)
        return None


def normalize_host(value: str) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host[:253]


def client_ip(request: Request) -> str:
    raw = (
        request.headers.get("x-original-ip")
        or request.headers.get("x-real-ip")
        or (request.client.host if request.client else "")
        or "0.0.0.0"
    ).split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "0.0.0.0"


def subnet_identity(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        prefix = 24 if address.version == 4 else 64
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return f"{network.network_address}/{prefix}"
    except ValueError:
        return "0.0.0.0/24"


def user_agent(request: Request) -> str:
    return (
        request.headers.get("x-original-user-agent")
        or request.headers.get("user-agent")
        or ""
    )[:512]


def _ua_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


def _config_key(host: str) -> str:
    return f"waf:captcha:domain:{normalize_host(host)}"


def _default_config(host: str = "") -> dict:
    return {
        "origin_id": "",
        "domain": normalize_host(host),
        "enabled": False,
        "engine": "native",
        "login_paths": list(DEFAULT_PATHS),
        "clearance_ttl": DEFAULT_CLEARANCE_TTL,
        "bypass_ips": [],
        "pow_difficulty": 3,
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
        logger.warning("captcha config read failed for %s: %s", host, exc)
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
    if client is None or not config.get("enabled") or config.get("engine", "native") != "native":
        return "allow"
    if not _matches_path(path, config.get("login_paths", DEFAULT_PATHS)):
        return "allow"
    if _is_bypassed(client_ip(request), config.get("bypass_ips", [])):
        return "allow"
    return "allow" if _cookie_valid(request, host) else "challenge"


async def captcha_access(request: Request) -> Response:
    if access_decision(request) == "challenge":
        return Response(
            status_code=401,
            headers={"X-Captcha-Required": "1", "Cache-Control": "no-store"},
        )
    return Response(status_code=204)


def _new_challenge(request: Request, config: dict, client) -> dict:
    challenge_id = str(uuid.uuid4())
    record = {
        "host": normalize_host(request.headers.get("host", "")),
        "prefix": "waf-" + secrets.token_hex(16),
        "difficulty": max(1, min(5, int(config.get("pow_difficulty", 3)))),
        "ip_subnet": subnet_identity(client_ip(request)),
        "ua_digest": _ua_digest(user_agent(request)),
        "issued_at": int(time.time()),
    }
    client.setex(
        f"waf:captcha:challenge:{challenge_id}",
        CHALLENGE_TTL,
        json.dumps(record, separators=(",", ":")),
    )
    return {
        "challenge_id": challenge_id,
        "prefix": record["prefix"],
        "difficulty": record["difficulty"],
    }


def _challenge_html(payload: dict) -> str:
    # Values are generated by the server and limited to UUID/hex/integer fields.
    safe_payload = (
        json.dumps(payload, separators=(",", ":"))
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("</", "<\\/")
    )
    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e5e7eb;font:16px system-ui,sans-serif}}
main{{width:min(92vw,430px);padding:32px;border:1px solid #263248;border-radius:16px;background:#111a2b;box-shadow:0 18px 50px #0006;text-align:center}}
.spinner{{width:28px;height:28px;margin:20px auto;border:3px solid #334155;border-top-color:#fb923c;border-radius:50%;animation:spin 1s linear infinite}}
small{{color:#94a3b8}}#error{{color:#fca5a5;min-height:1.5em}}@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style></head><body><main>
<h1>กำลังตรวจสอบเบราว์เซอร์</h1><p>กรุณารอสักครู่ ระบบกำลังยืนยันความปลอดภัยก่อนเข้าสู่ระบบ</p>
<div class="spinner" aria-hidden="true"></div><small id="status">กำลังคำนวณ...</small><p id="error"></p>
</main><script>
const challenge=JSON.parse('{safe_payload}'),statusEl=document.getElementById('status'),errorEl=document.getElementById('error');
function rotr(n,x){{return(x>>>n)|(x<<(32-n));}}
function sha256Fallback(input){{
 const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 let h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],bytes=unescape(encodeURIComponent(input)),bits=bytes.length*8,data=[];
 for(let i=0;i<bytes.length;i++)data.push(bytes.charCodeAt(i));data.push(128);while(data.length%64!==56)data.push(0);
 data.push(0,0,0,0,(bits>>>24)&255,(bits>>>16)&255,(bits>>>8)&255,bits&255);
 for(let off=0;off<data.length;off+=64){{let w=new Array(64);for(let i=0;i<16;i++)w[i]=(data[off+4*i]<<24)|(data[off+4*i+1]<<16)|(data[off+4*i+2]<<8)|data[off+4*i+3];for(let i=16;i<64;i++){{let s0=rotr(7,w[i-15])^rotr(18,w[i-15])^(w[i-15]>>>3),s1=rotr(17,w[i-2])^rotr(19,w[i-2])^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}}let[a,b,c,d,e,f,g,j]=h;for(let i=0;i<64;i++){{let S1=rotr(6,e)^rotr(11,e)^rotr(25,e),ch=(e&f)^((~e)&g),t1=(j+S1+ch+K[i]+w[i])|0,S0=rotr(2,a)^rotr(13,a)^rotr(22,a),maj=(a&b)^(a&c)^(b&c),t2=(S0+maj)|0;j=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}}h=h.map((v,i)=>(v+[a,b,c,d,e,f,g,j][i])|0);}}
 return h.map(x=>('00000000'+(x>>>0).toString(16)).slice(-8)).join('');
}}
async function sha256Hex(value){{if(window.crypto&&window.crypto.subtle&&window.TextEncoder){{const b=await window.crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');}}return sha256Fallback(value);}}
async function solve(){{const target='0'.repeat(challenge.difficulty);let nonce=0,started=Date.now();while(nonce<=2000000){{if(nonce%256===0)statusEl.textContent='กำลังคำนวณ... '+Math.round((Date.now()-started)/1000)+' วินาที';const digest=await sha256Hex(challenge.prefix+nonce);if(digest.startsWith(target)){{const r=await fetch('/cdn-cgi/challenge/verify',{{method:'POST',credentials:'same-origin',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{challenge_id:challenge.challenge_id,nonce:nonce,host:location.host}})}}),j=await r.json().catch(()=>({{}}));if(r.ok&&j.success){{location.reload();return;}}throw new Error(j.error||'verification failed');}}nonce++;}}throw new Error('challenge timeout');}}
solve().catch(e=>{{document.querySelector('.spinner').style.display='none';statusEl.textContent='ไม่สามารถยืนยันเบราว์เซอร์ได้';errorEl.textContent=e.message+' กรุณาลองใหม่';}});
</script></body></html>"""


async def issue_challenge(request: Request) -> Response:
    host = normalize_host(request.headers.get("host", ""))
    config, client = get_config(host)
    if client is None:
        return Response(status_code=503, content="Challenge service temporarily unavailable")
    if not config.get("enabled") or config.get("engine", "native") != "native":
        return Response(status_code=404, content="Not found")
    try:
        return HTMLResponse(
            _challenge_html(_new_challenge(request, config, client)),
            headers={"Cache-Control": "no-store, no-cache", "Pragma": "no-cache"},
        )
    except Exception as exc:
        logger.exception("challenge issuance failed: %s", exc)
        return Response(status_code=503, content="Challenge service temporarily unavailable")


def _verify_rate_limited(client, address: str) -> bool:
    try:
        key = f"waf:captcha:verify-rate:{address}"
        count = int(client.incr(key))
        if count == 1:
            client.expire(key, 60)
        return count > 10
    except Exception:
        return True


async def verify_challenge(request: Request, payload: ChallengeVerifyRequest) -> Response:
    client = _redis()
    if client is None:
        return JSONResponse({"success": False, "error": "verification unavailable"}, status_code=503)
    address = client_ip(request)
    if _verify_rate_limited(client, address):
        return JSONResponse({"success": False, "error": "too many attempts"}, status_code=429)
    host = normalize_host(request.headers.get("host", ""))
    if not host or host != normalize_host(payload.host):
        return JSONResponse({"success": False, "error": "host mismatch"}, status_code=400)
    try:
        raw = client.eval(
            "local v=redis.call('GET',KEYS[1]); if v then redis.call('DEL',KEYS[1]); end; return v",
            1,
            f"waf:captcha:challenge:{payload.challenge_id}",
        )
        if not raw:
            return JSONResponse({"success": False, "error": "challenge expired"}, status_code=400)
        record = json.loads(raw)
    except Exception as exc:
        logger.warning("challenge lookup failed: %s", exc)
        return JSONResponse({"success": False, "error": "verification unavailable"}, status_code=503)
    if (
        record.get("host") != host
        or record.get("ip_subnet") != subnet_identity(address)
        or record.get("ua_digest") != _ua_digest(user_agent(request))
    ):
        return JSONResponse({"success": False, "error": "challenge context mismatch"}, status_code=400)
    digest = hashlib.sha256(
        (str(record.get("prefix", "")) + str(payload.nonce)).encode("utf-8")
    ).hexdigest()
    difficulty = max(1, min(5, int(record.get("difficulty", 3))))
    if not digest.startswith("0" * difficulty):
        return JSONResponse({"success": False, "error": "invalid proof"}, status_code=400)
    config, _ = get_config(host, client)
    ttl = max(900, min(43200, int(config.get("clearance_ttl", DEFAULT_CLEARANCE_TTL))))
    expiry = int(time.time()) + ttl
    message = "\x1f".join([subnet_identity(address), user_agent(request), host, str(expiry)])
    signature = hmac.new(
        HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    response = JSONResponse({"success": True})
    response.set_cookie(
        COOKIE_NAME, f"{expiry}.{host}.{signature}", max_age=ttl, expires=expiry,
        path="/", secure=True, httponly=True, samesite="lax"
    )
    return response
