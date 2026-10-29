import base64
import functools
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import math
import os
import secrets
import socket
import time
import uuid
from http.cookies import SimpleCookie

import redis
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from PIL import Image, ImageDraw, ImageFont
from pydantic import BaseModel, Field

from shield_paths import is_protected

logger = logging.getLogger(__name__)
COOKIE_NAME = "waf_clearance"
DEFAULT_PATHS = ["/login*", "/admin*", "/wp-login.php", "/administrator*", "/user/login*"]
CHALLENGE_TTL = 60
# A visitor reads and types the image text, so its challenge lives longer
# than the proof-of-work one the browser solves on its own.
IMAGE_CHALLENGE_TTL = 180
# No 0/O, 1/I/L: characters people confuse in a distorted image.
IMAGE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
IMAGE_LENGTH = 5
IMAGE_SIZE = (200, 70)
DEFAULT_CLEARANCE_TTL = 3600
CLEARANCE_TTL_RANGE = (900, 43200)
# A cookie's expiry may run past now + the configured clearance by at most
# this much (clock differences between workers), never more.
EXPIRY_SKEW_SECONDS = 60
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
# host -> origin_id of the verified hosts, written by the dashboard
# (dashboard/backend/services/shield_sync.py). A per-domain config only
# counts while its origin_id is the host's current owner here.
HOSTMAP_KEY = "waf:shield:hostmap"
_redis_client = None


def required_secret(name: str) -> str:
    """N6: the clearance cookies are signed with a key of their own, set in
    the environment. No fallback to CONTROL_TOKEN (shared with other jobs) and
    none to a random per-process key (every worker would reject the others'
    cookies): without the key the service does not start."""
    value = os.getenv(name, "")
    if len(value) < 32:
        raise RuntimeError(f"{name} must be set to a random value of at least 32 characters")
    if value == os.getenv("CONTROL_TOKEN", ""):
        raise RuntimeError(f"{name} must not be the same value as CONTROL_TOKEN")
    return value


HMAC_SECRET = required_secret("CAPTCHA_HMAC_SECRET")


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    nonce: int = Field(ge=0, le=2_000_000)
    host: str = Field(min_length=1, max_length=253)
    # The text typed from the image; only checked when the challenge has one.
    answer: str | None = Field(default=None, max_length=16)


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


# P2.5 (H18/H19): the X-Original-IP / X-Real-IP headers are believed only
# from the WAF's own nginx, which sets them from the visitor's real address.
# Anyone else reaching this service (an edge pulling the rule bundle, a host
# process) is identified by its own address.
_TRUSTED_PROXIES = [
    item.strip()
    for item in os.getenv("SHIELD_TRUSTED_PROXIES", "waf-nginx").split(",")
    if item.strip()
]
_TRUSTED_CACHE_SECONDS = 30
_trusted_cache = {"at": None, "nets": [], "names": set()}


def _trusted_networks() -> tuple:
    now = time.monotonic()
    if _trusted_cache["at"] is not None and now - _trusted_cache["at"] < _TRUSTED_CACHE_SECONDS:
        return _trusted_cache["nets"], _trusted_cache["names"]
    nets, names = [], set()
    for item in _TRUSTED_PROXIES:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            names.add(item)
        try:
            # A container name: resolved through Docker's DNS, so a recreated
            # waf-nginx with a new address is picked up within the cache time.
            for info in socket.getaddrinfo(item, None):
                nets.append(ipaddress.ip_network(info[4][0], strict=False))
        except OSError:
            pass
    _trusted_cache.update(at=now, nets=nets, names=names)
    return nets, names


def _from_trusted_proxy(peer: str) -> bool:
    nets, names = _trusted_networks()
    if peer in names:
        return True
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in net for net in nets)


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    raw = peer
    if _from_trusted_proxy(peer):
        raw = request.headers.get("x-original-ip") or request.headers.get("x-real-ip") or peer
    raw = (raw or "0.0.0.0").split(",", 1)[0].strip()
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
        # On top of the proof of work, the visitor types the text of a
        # distorted image. Off unless the origin turns it on.
        "image_captcha": False,
        # "enforce" or "log_only" (record what would happen, let the request
        # through). Configs saved before this field existed have no key and
        # keep enforcing.
        "mode": "enforce",
        "exclude_paths": [],
    }


# H83: the last enabled config seen per (gate, host), used while Redis cannot
# be read so a protected path is not left open. Only enabled configs are
# kept, and the size is capped: the Host header is chosen by the client.
_LAST_KNOWN_MAX = 5000
_last_known: dict = {}


def remember_config(kind: str, host: str, config: dict) -> None:
    key = (kind, host)
    if not config.get("enabled"):
        _last_known.pop(key, None)
        return
    if key not in _last_known and len(_last_known) >= _LAST_KNOWN_MAX:
        _last_known.pop(next(iter(_last_known)))
    _last_known[key] = dict(config)


def last_known_config(kind: str, host: str, default: dict) -> dict:
    return dict(_last_known.get((kind, host)) or default)


def owned_config(client, host: str, value, default: dict) -> dict:
    """C1/H39/N11: a stored per-domain config applies only while its origin
    is the host's current owner in the dashboard's host map. A key left
    behind by a removed domain or origin falls back to the default (off), so
    whoever adds the domain next does not inherit the previous owner's
    settings."""
    result = dict(default)
    if not isinstance(value, dict):
        return result
    origin_id = str(value.get("origin_id") or "")
    owner = client.hget(HOSTMAP_KEY, normalize_host(host))
    if not origin_id or owner != origin_id:
        return result
    result.update(value)
    return result


def get_config(host: str, client=None) -> tuple[dict, object | None]:
    host = normalize_host(host)
    client = client if client is not None else _redis()
    if client is None:
        return last_known_config("captcha", host, _default_config(host)), None
    try:
        raw = client.get(_config_key(host))
        value = json.loads(raw) if raw else None
        result = owned_config(client, host, value, _default_config(host))
    except Exception as exc:
        logger.warning("captcha config read failed for %s: %s", host, exc)
        return last_known_config("captcha", host, _default_config(host)), None
    remember_config("captcha", host, result)
    return result, client


def max_cookie_expiry(config: dict, ttl_range: tuple) -> int:
    ttl = max(ttl_range[0], min(ttl_range[1], int(config.get("clearance_ttl", DEFAULT_CLEARANCE_TTL))))
    return int(time.time()) + ttl + EXPIRY_SKEW_SECONDS


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


def _cookie_valid(request: Request, host: str, config: dict | None = None) -> bool:
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
    expiry, _, rest = value.partition(".")
    cookie_host, _, signature = rest.rpartition(".")
    if not cookie_host or not signature:
        return False
    if not expiry.isdigit() or int(expiry) <= int(time.time()):
        return False
    # N6: the expiry is signed, but a cookie claiming to last longer than the
    # configured clearance is refused all the same.
    if int(expiry) > max_cookie_expiry(config or _default_config(host), CLEARANCE_TTL_RANGE):
        return False
    if normalize_host(cookie_host) != host:
        return False
    message = "\x1f".join([subnet_identity(client_ip(request)), user_agent(request), host, expiry])
    expected = hmac.new(
        HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def has_clearance(request: Request) -> bool:
    """A valid CAPTCHA clearance cookie for the request's host, whatever the
    host's CAPTCHA setting (the ML challenge issues the same cookie)."""
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    config, _ = get_config(host)
    return _cookie_valid(request, host, config)


def access_decision(request: Request) -> str:
    # Every method is gated, not only GET/HEAD: the old GET/HEAD-only check let a
    # script POST credentials straight to a protected login path without ever
    # seeing the challenge (found 2026-09-29: POST to a protected path returned
    # 200 with no clearance cookie). shield_access answers non-GET requests with
    # a plain 403 instead of the HTML page. OPTIONS stays open: a CORS preflight
    # never carries cookies, so gating it would break a browser that already
    # holds clearance.
    original_method = request.headers.get("x-original-method", request.method).upper()
    if original_method == "OPTIONS":
        return "allow"
    host = normalize_host(request.headers.get("x-original-host") or request.headers.get("host", ""))
    config, client = get_config(host)
    if not config.get("enabled") or config.get("engine", "native") != "native":
        return "allow"
    if not is_protected(request.headers.get("x-original-uri", "/"),
                        config.get("login_paths", DEFAULT_PATHS), config.get("exclude_paths")):
        return "allow"
    if _is_bypassed(client_ip(request), config.get("bypass_ips", [])):
        return "allow"
    if _cookie_valid(request, host, config):
        return "allow"
    if client is None:
        # H83: Redis is down, so no challenge can be issued or recorded. A
        # log-only gate lets the request through as it always does; an
        # enforcing one answers "unavailable" instead of opening the path.
        return "allow" if config.get("mode") == "log_only" else "unavailable"
    return "challenge"


async def captcha_access(request: Request) -> Response:
    if access_decision(request) == "challenge":
        return Response(
            status_code=401,
            headers={"X-Captcha-Required": "1", "Cache-Control": "no-store"},
        )
    return Response(status_code=204)


def _answer_digest(challenge_id: str, answer: str) -> str:
    normalized = "".join(answer.split()).upper()
    return hmac.new(
        HMAC_SECRET.encode("utf-8"),
        f"image\x1f{challenge_id}\x1f{normalized}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


_rng = secrets.SystemRandom()


@functools.lru_cache(maxsize=16)
def _image_font(size: int):
    # Pillow's bundled FreeType font: the slim image ships no system fonts.
    return ImageFont.load_default(size=size)


def _captcha_png(text: str) -> bytes:
    width, height = IMAGE_SIZE
    image = Image.new("RGB", IMAGE_SIZE, tuple(_rng.randint(225, 250) for _ in range(3)))
    draw = ImageDraw.Draw(image)
    for _ in range(350):
        draw.point(
            (_rng.randrange(width), _rng.randrange(height)),
            fill=tuple(_rng.randint(110, 210) for _ in range(3)),
        )
    # Each character on its own layer: its own size, tilt and offset, so the
    # glyphs do not sit on one baseline a segmenter can cut along.
    cell = 60
    step = (width - 20) / len(text)
    for index, char in enumerate(text):
        glyph = Image.new("RGBA", (cell, cell), (0, 0, 0, 0))
        ImageDraw.Draw(glyph).text(
            (cell / 2, cell / 2), char, anchor="mm",
            font=_image_font(_rng.randint(34, 42)),
            fill=tuple(_rng.randint(10, 110) for _ in range(3)) + (255,),
        )
        glyph = glyph.rotate(_rng.uniform(-22, 22), resample=Image.BICUBIC)
        x = int(10 + index * step - (cell - step) / 2 + _rng.uniform(-3, 3))
        y = int((height - cell) / 2 + _rng.uniform(-6, 6))
        image.paste(glyph, (x, y), glyph)
    # A vertical sine wave across the whole text bends every glyph a little.
    amplitude, period, phase = _rng.uniform(2.5, 4.5), _rng.uniform(45, 75), _rng.uniform(0, 2 * math.pi)
    waved = image.copy()
    for x in range(width):
        dy = int(amplitude * math.sin(2 * math.pi * x / period + phase))
        waved.paste(image.crop((x, 0, x + 1, height)), (x, dy))
    draw = ImageDraw.Draw(waved)
    for _ in range(3):
        draw.line(
            [(0, _rng.randrange(height)), (width // 2, _rng.randrange(height)), (width, _rng.randrange(height))],
            fill=tuple(_rng.randint(40, 140) for _ in range(3)),
            width=2,
            joint="curve",
        )
    out = io.BytesIO()
    waved.save(out, format="PNG", optimize=True)
    return out.getvalue()


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
    text = None
    if config.get("image_captcha"):
        text = "".join(secrets.choice(IMAGE_ALPHABET) for _ in range(IMAGE_LENGTH))
        record["answer_digest"] = _answer_digest(challenge_id, text)
    client.setex(
        f"waf:captcha:challenge:{challenge_id}",
        IMAGE_CHALLENGE_TTL if text else CHALLENGE_TTL,
        json.dumps(record, separators=(",", ":")),
    )
    payload = {
        "challenge_id": challenge_id,
        "prefix": record["prefix"],
        "difficulty": record["difficulty"],
    }
    if text:
        payload["image"] = "data:image/png;base64," + base64.b64encode(_captcha_png(text)).decode("ascii")
    return payload


def _challenge_html(payload: dict) -> str:
    # The image stays out of the script: it goes into the <img> tag, and the
    # script only learns that there is one.
    payload = dict(payload)
    image = payload.pop("image", None)
    payload["image"] = bool(image)
    # Values are generated by the server and limited to UUID/hex/integer/bool fields.
    safe_payload = (
        json.dumps(payload, separators=(",", ":"))
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("</", "<\\/")
    )
    if image:
        # The data URI is base64 of a PNG the server drew: no quotes or markup.
        body = f"""<h1>ยืนยันว่าคุณไม่ใช่บอท</h1><p>พิมพ์ตัวอักษรที่เห็นในภาพเพื่อเข้าสู่ระบบ</p>
<img id="captcha-image" src="{image}" width="{IMAGE_SIZE[0]}" height="{IMAGE_SIZE[1]}" alt="ภาพตัวอักษรสำหรับยืนยันตัวตน">
<form id="captcha-form"><input id="captcha-answer" name="answer" maxlength="16" autocomplete="off" autocapitalize="characters" spellcheck="false" required aria-label="ตัวอักษรในภาพ"><button type="submit">ยืนยัน</button></form>
<button type="button" id="captcha-refresh" class="link">ขอภาพใหม่</button>
<small id="status"></small><p id="error"></p>"""
    else:
        body = """<h1>กำลังตรวจสอบเบราว์เซอร์</h1><p>กรุณารอสักครู่ ระบบกำลังยืนยันความปลอดภัยก่อนเข้าสู่ระบบ</p>
<div class="spinner" aria-hidden="true"></div><small id="status">กำลังคำนวณ...</small><p id="error"></p>"""
    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e5e7eb;font:16px system-ui,sans-serif}}
main{{width:min(92vw,430px);padding:32px;border:1px solid #263248;border-radius:16px;background:#111a2b;box-shadow:0 18px 50px #0006;text-align:center}}
.spinner{{width:28px;height:28px;margin:20px auto;border:3px solid #334155;border-top-color:#fb923c;border-radius:50%;animation:spin 1s linear infinite}}
small{{color:#94a3b8}}#error{{color:#fca5a5;min-height:1.5em}}@keyframes spin{{to{{transform:rotate(360deg)}}}}
#captcha-image{{display:block;margin:20px auto 16px;border-radius:8px;max-width:100%;height:auto}}
#captcha-form{{display:flex;gap:8px;margin:0 0 12px}}
#captcha-answer{{flex:1;min-width:0;padding:10px 12px;border:1px solid #334155;border-radius:8px;background:#0b1220;color:#e5e7eb;font:600 18px ui-monospace,monospace;letter-spacing:.2em;text-transform:uppercase}}
#captcha-form button{{padding:10px 16px;border:0;border-radius:8px;background:#fb923c;color:#111827;font-weight:700;cursor:pointer}}
#captcha-form button:disabled{{opacity:.6;cursor:wait}}
.link{{display:block;margin:0 auto 8px;border:0;background:none;color:#93c5fd;font:inherit;font-size:14px;cursor:pointer;text-decoration:underline}}
</style></head><body><main>
{body}
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
async function work(){{const target='0'.repeat(challenge.difficulty);let nonce=0,started=Date.now();while(nonce<=2000000){{if(!challenge.image&&nonce%256===0)statusEl.textContent='กำลังคำนวณ... '+Math.round((Date.now()-started)/1000)+' วินาที';const digest=await sha256Hex(challenge.prefix+nonce);if(digest.startsWith(target))return nonce;nonce++;}}throw new Error('challenge timeout');}}
async function send(nonce,answer){{const body={{challenge_id:challenge.challenge_id,nonce:nonce,host:location.host}};if(answer!==undefined)body.answer=answer;const r=await fetch('/cdn-cgi/challenge/verify',{{method:'POST',credentials:'same-origin',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}}),j=await r.json().catch(()=>({{}}));if(r.ok&&j.success){{location.reload();return;}}throw new Error(j.error||'verification failed');}}
const proof=work();
if(!challenge.image){{proof.then(nonce=>send(nonce)).catch(e=>{{document.querySelector('.spinner').style.display='none';statusEl.textContent='ไม่สามารถยืนยันเบราว์เซอร์ได้';errorEl.textContent=e.message+' กรุณาลองใหม่';}});}}
else{{
 // The proof of work runs while the visitor reads the image. A challenge is
 // good for one attempt only, so any failure loads a fresh image.
 proof.catch(()=>{{}});
 const form=document.getElementById('captcha-form'),input=document.getElementById('captcha-answer'),button=form.querySelector('button');
 document.getElementById('captcha-refresh').addEventListener('click',()=>location.reload());
 input.focus();
 form.addEventListener('submit',async e=>{{e.preventDefault();const answer=input.value.trim();if(!answer){{input.focus();return;}}button.disabled=true;input.disabled=true;errorEl.textContent='';statusEl.textContent='กำลังตรวจสอบ...';try{{await send(await proof,answer);}}catch(err){{statusEl.textContent='';errorEl.textContent=(err.message==='invalid answer'?'ตัวอักษรไม่ถูกต้อง':err.message)+' กำลังโหลดภาพใหม่...';setTimeout(()=>location.reload(),1500);}}}});
}}
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
    # The record is already deleted above, so a wrong answer costs the whole
    # challenge: guessing means a new image and a new proof of work each time.
    expected_answer = record.get("answer_digest")
    if expected_answer and not hmac.compare_digest(
        expected_answer, _answer_digest(payload.challenge_id, payload.answer or "")
    ):
        return JSONResponse({"success": False, "error": "invalid answer"}, status_code=400)
    config, _ = get_config(host, client)
    ttl = max(CLEARANCE_TTL_RANGE[0], min(CLEARANCE_TTL_RANGE[1], int(config.get("clearance_ttl", DEFAULT_CLEARANCE_TTL))))
    expiry = int(time.time()) + ttl
    message = "\x1f".join([subnet_identity(address), user_agent(request), host, str(expiry)])
    signature = hmac.new(
        HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    response = JSONResponse({"success": True})
    # No expires=: Starlette reads an int there as seconds from now, so the
    # absolute expiry put Expires decades ahead. max_age alone sets the same
    # lifetime, and the signed expiry in the value is what the server checks.
    response.set_cookie(
        COOKIE_NAME, f"{expiry}.{host}.{signature}", max_age=ttl,
        path="/", secure=True, httponly=True, samesite="lax"
    )
    return response
