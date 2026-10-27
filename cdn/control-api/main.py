import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import sqlite3
import tarfile
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from captcha_engine import captcha_access, issue_challenge, verify_challenge, ChallengeVerifyRequest
from captcha_engine import _redis as shared_redis
from captcha_engine import has_clearance
from otp_engine import otp_access, shield_access, issue_challenge_page, issue_ml_challenge, request_code, verify_code, OtpRequestPayload, OtpVerifyPayload

# 2026-09-22 (overnight session): this service is bound 0.0.0.0:8070 (see
# docker-compose.yml) because edge nodes may need to reach /api/sync/bundle
# over the public internet -- confirmed this is a real architectural
# question (the edges' own sync script defaults CONTROL_API_URL to an
# internal docker hostname, "cdn-control-api", which only resolves if each
# edge runs its own local copy of this service; whether the real deployed
# edge-th/edge-asia machines override that to Main's public IP could not be
# verified without SSH access to those machines, which this session did not
# have). That question -- and whatever token/IP-allowlist fix
# /api/blocklist and /api/sync/bundle need -- is deliberately left
# untouched here rather than guessed at overnight with no way to verify the
# edges kept syncing. /docs, /redoc and /openapi.json have no such
# constraint: nothing functional depends on them, and disabling them is the
# same safe, already-proven pattern dashboard/backend/main.py's own
# FastAPI app uses for the identical reason (F2, 2026-09-08 web assessment:
# an unauthenticated docs page enumerates every endpoint on the service).
app = FastAPI(
    title="CDN Control API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

DATA_DIR = Path(os.getenv("CONTROL_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "control.db"

RULES_DIR = Path(os.getenv("CUSTOM_RULES_DIR", "/src/custom-rules"))

CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "")

# 2026-09-23: GET /api/blocklist and GET /api/sync/bundle were reachable by
# anyone on the internet (this service is published on 0.0.0.0:8070 so the
# edges can reach it -- see the note at the top of this file). Between them
# they hand out the full ModSecurity rule bundle and every blocked IP:
# an attacker could read exactly which rules exist before probing, and
# check whether their own address is blocked. The writes here have always
# required CONTROL_TOKEN; the reads required nothing.
#
# Fixed with a source-IP allow-list rather than a token because the edges'
# own sync script calls the bundle with a plain unauthenticated curl
# (edge_node/edge/entrypoint.d/99-rulesync.sh), so requiring a header would
# have silently stopped rule and blocklist propagation to both edges. Both
# addresses below are already proven to be the edges' real egress IPs --
# dashboard/backend/api/cdn.py gates /api/cdn/logs/ingest on the same list
# and both forwarders are delivering through it.
#
# 10.88.0.2/10.88.0.3 are the same edges over WireGuard (2026-10-15,
# deploy/wireguard/README.md); dashboard/backend/services/edge_tunnel.py
# holds the same pair.
#
# P4.4 (H07): only the edges' WireGuard addresses. The public IPs no longer
# reach this port at all (close-public-path.sh), and loopback / the docker
# gateways let any process on Main, or any container, read the full rule
# bundle and blocklist.
_EDGE_ALLOWED_IPS = {
    ip.strip()
    for ip in os.getenv("EDGE_ALLOWED_IPS", "10.88.0.2,10.88.0.3").split(",")
    if ip.strip()
}


def _require_edge_source(request: Request):
    """404 rather than 403: an unauthorised caller learns nothing about
    whether this path exists, matching how api/cdn.py's ingest endpoint
    already refuses non-edge callers."""
    client_host = request.client.host if request.client else ""
    if client_host not in _EDGE_ALLOWED_IPS:
        raise HTTPException(status_code=404, detail="Not found")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL, source TEXT NOT NULL)"
    )
    return conn


class BlockRequest(BaseModel):
    ip: str
    source: str = "manual"


def _require_token(token: str):
    # P4.4 (H08): constant-time comparison.
    if not CONTROL_TOKEN or not hmac.compare_digest(str(token).encode(), CONTROL_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="Invalid control token")


def canonical_ip(value: str) -> str:
    """P4.4 (H06): an IP address or CIDR network, in canonical text; anything
    else is a ValueError. One malformed line in global_blocklist.txt makes
    @ipMatchFromFile fail nginx -t on every edge, which then stopped taking
    any rule update at all."""
    text = str(value or "").strip()
    if "/" in text:
        return str(ipaddress.ip_network(text, strict=False))
    return str(ipaddress.ip_address(text))


def _valid_ips(values) -> list:
    out = []
    for value in values:
        try:
            ip = canonical_ip(value)
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


# ------------------------------------------------------------------ P4.1
# The bundle carries a version that only goes up and an HMAC over
# "<version>:<sha256 of the body>" with BUNDLE_SIGNING_KEY, shared with the
# edges. An edge applies a bundle only when the signature checks and the
# version is newer than the one it runs (cdn/edge/entrypoint.d/99-rulesync.sh),
# so neither a tampered nor a replayed older bundle is taken.
BUNDLE_SIGNING_KEY = os.getenv("BUNDLE_SIGNING_KEY", "")
_BUNDLE_STATE = DATA_DIR / "bundle_state.json"
_bundle_lock = threading.Lock()


def _bundle_version(body_sha: str) -> int:
    """The version for this bundle content: unchanged content keeps its
    version, new content gets the next number. Persisted in the data volume."""
    with _bundle_lock:
        try:
            state = json.loads(_BUNDLE_STATE.read_text())
        except (OSError, ValueError):
            state = {"version": 0, "sha": ""}
        if state.get("sha") != body_sha:
            state = {"version": int(state.get("version", 0)) + 1, "sha": body_sha}
            tmp = _BUNDLE_STATE.with_suffix(".tmp")
            tmp.write_text(json.dumps(state))
            tmp.replace(_BUNDLE_STATE)
        return int(state["version"])


def bundle_signature(version: int, body: bytes, key: str = None) -> str:
    key = BUNDLE_SIGNING_KEY if key is None else key
    message = f"{version}:{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def _block_rule_content() -> str:
    return (
        "# Auto-generated: global blocklist\n"
        "SecRule REMOTE_ADDR \"@ipMatchFromFile /opt/custom-rules/global_blocklist.txt\" \\\n"
        "\"id:1000000,phase:1,deny,status:403,log,msg:'Global blocklist (synced)'\"\n"
    )


@app.api_route("/api/captcha/access", methods=["GET", "POST"], include_in_schema=False)
async def captcha_access_route(request: Request):
    return await captcha_access(request)

@app.api_route("/api/shield/access", methods=["GET", "POST"], include_in_schema=False)
async def shield_access_route(request: Request):
    # Combined captcha+OTP+ML auth_request target -- see
    # otp_engine.shield_access for why nginx needs one endpoint deciding
    # all three instead of separate hooks.
    return await shield_access(request)

@app.get("/cdn-cgi/challenge", include_in_schema=False)
async def captcha_challenge_route(request: Request):
    # nginx forwards the failing gate's kind on X-Shield-Type (set from the
    # shield_access response header via auth_request_set); default to
    # captcha for direct/manual hits that carry no such header.
    shield_type = request.headers.get("x-shield-type")
    if shield_type == "ratelimit":
        # P2.6: over a rate-limit rule. nginx forwards the Retry-After the
        # shield check computed on X-Retry-After.
        retry_after = request.headers.get("x-retry-after", "")
        return Response(
            status_code=429,
            content="Too Many Requests. Rate limit exceeded. Please try again later.",
            media_type="text/plain",
            headers={"Retry-After": retry_after if retry_after.isdigit() else "60", "Cache-Control": "no-store"},
        )
    if shield_type == "unavailable":
        # H83: a protected path while the shield's store is down.
        return Response(
            status_code=503,
            content="Service temporarily unavailable. Please try again shortly.",
            media_type="text/plain",
            headers={"Retry-After": "30", "Cache-Control": "no-store"},
        )
    if shield_type == "otp":
        return await issue_challenge_page(request)
    if shield_type == "ml":
        return await issue_ml_challenge(request)
    return await issue_challenge(request)

@app.post("/cdn-cgi/challenge/verify", include_in_schema=False)
async def captcha_verify_route(request: Request, payload: ChallengeVerifyRequest):
    return await verify_challenge(request, payload)

@app.get("/api/ml/clearance", include_in_schema=False)
async def ml_clearance_route(request: Request):
    # The challenge band of the per-origin inline ML gate (nginx/njs/mlgate.js):
    # 204 when the visitor already holds a valid CAPTCHA clearance for the
    # host, 401 when not -- the same check shield_access makes for its own ML
    # branch (H10). nginx sends the visitor's address, UA and cookie, so a
    # cookie only counts for the visitor it was issued to.
    return Response(status_code=204 if has_clearance(request) else 401, headers={"Cache-Control": "no-store"})

@app.api_route("/api/otp/access", methods=["GET", "POST"], include_in_schema=False)
async def otp_access_route(request: Request):
    # Standalone/manual use only -- not wired into nginx (see shield_access).
    return await otp_access(request)

@app.get("/cdn-cgi/otp-challenge", include_in_schema=False)
async def otp_challenge_route(request: Request):
    return await issue_challenge_page(request)

@app.post("/cdn-cgi/otp/request", include_in_schema=False)
async def otp_request_route(request: Request, payload: OtpRequestPayload):
    return await request_code(request, payload)

@app.post("/cdn-cgi/otp/verify", include_in_schema=False)
async def otp_verify_route(request: Request, payload: OtpVerifyPayload):
    return await verify_code(request, payload)

@app.get("/healthz")
def healthz():
    return {"status": "ok", "rules_dir": str(RULES_DIR)}


@app.get("/api/blocklist")
def get_blocklist(request: Request) -> dict:
    _require_edge_source(request)
    conn = db()
    rows = conn.execute("SELECT ip, created_at, source FROM blocklist ORDER BY created_at DESC").fetchall()
    conn.close()
    return {
        "items": [
            {"ip": ip, "created_at": created_at, "source": source}
            for (ip, created_at, source) in rows
        ]
    }


@app.post("/api/blocklist")
def add_block(req: BlockRequest, x_control_token: str = Header(default="")) -> dict:
    _require_token(x_control_token)
    try:
        ip = canonical_ip(req.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="ip must be an IP address or CIDR network")

    conn = db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO blocklist(ip, created_at, source) VALUES(?, ?, ?)",
            (ip, int(time.time()), (req.source or "manual")[:64]),
        )
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "ip": ip}


@app.delete("/api/blocklist/{ip}")
def remove_block(ip: str, x_control_token: str = Header(default="")) -> dict:
    _require_token(x_control_token)

    conn = db()
    try:
        try:
            ip = canonical_ip(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="ip must be an IP address or CIDR network")
        conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "ip": ip}


# Edge cache purge queue, written by the dashboard
# (dashboard/backend/services/cdn_purge.py -- same keys and line format).
PURGE_SEQ_KEY = "cdn:purge:seq"
PURGE_JOBS_KEY = "cdn:purge:jobs"
PURGE_ACKS_KEY = "cdn:purge:acks"
PURGE_BATCH = 500
_PURGE_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def purge_signature(body: bytes, key: str = None) -> str:
    key = BUNDLE_SIGNING_KEY if key is None else key
    message = f"purge:{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def _purge_line_ok(line: str) -> bool:
    parts = line.split("\t")
    if len(parts) != 3 or not parts[0].isdigit() or not _PURGE_HOST_RE.match(parts[1]):
        return False
    path = parts[2]
    return path.startswith("/") and len(path) <= 2048 and all(0x20 < ord(c) != 0x7F for c in path)


@app.get("/api/sync/purges")
def get_purges(request: Request, after: int = 0) -> Response:
    """Purge jobs newer than `after` (the last one this edge applied), as
    "latest\t<id>" followed by "<id>\t<host>\t<path>" lines, signed like the
    rule bundle. The call also records how far this edge has got, which the
    dashboard shows per edge."""
    _require_edge_source(request)
    if not BUNDLE_SIGNING_KEY:
        raise HTTPException(status_code=503, detail="Bundle signing key is not configured")
    r = shared_redis()
    if r is None:
        raise HTTPException(status_code=503, detail="Purge queue unavailable")
    after = max(0, int(after))
    latest = int(r.get(PURGE_SEQ_KEY) or 0)
    jobs = r.zrangebyscore(PURGE_JOBS_KEY, after + 1, "+inf", start=0, num=PURGE_BATCH)
    if len(jobs) == PURGE_BATCH:
        # More than one batch behind: hand out this batch, the rest next time.
        latest = int(jobs[-1].split("\t", 1)[0])
    lines = [j for j in jobs if _purge_line_ok(j)]
    body = (f"latest\t{latest}\n" + "".join(f"{j}\n" for j in lines)).encode()
    edge = request.client.host if request.client else ""
    r.hset(PURGE_ACKS_KEY, edge, f"{min(after, latest)}:{int(time.time())}")
    return Response(content=body, media_type="text/plain", headers={
        "X-Purge-Signature": purge_signature(body),
        "Cache-Control": "no-store",
    })


@app.get("/api/sync/bundle")
def get_bundle(request: Request) -> Response:
    _require_edge_source(request)
    # Build a gzip tar with rules + global blocklist assets from RULES_DIR
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        # 1. Add all .conf and .txt files from RULES_DIR
        if RULES_DIR.exists():
            for p in sorted(RULES_DIR.glob("*")):
                # The blocklist file is added below, validated and merged.
                if p.name == "global_blocklist.txt":
                    continue
                if p.is_file() and (p.suffix in [".conf", ".txt", ".data"] or p.name.endswith(".conf") or p.name.endswith(".txt")):
                    data = p.read_bytes()
                    info = tarfile.TarInfo(name=p.name)
                    info.size = len(data)
                    # Content only: a rewrite with the same text must not
                    # look like a new bundle (and a new version) to the edges.
                    info.mtime = 0
                    tar.addfile(info, io.BytesIO(data))

        # 2. If global_blocklist.txt exists in control.db but not in RULES_DIR, merge
        conn = db()
        rows = conn.execute("SELECT ip FROM blocklist ORDER BY created_at DESC").fetchall()
        conn.close()
        db_ips = [ip for (ip,) in rows if ip]

        bl_file = RULES_DIR / "global_blocklist.txt"
        file_ips = []
        if bl_file.exists():
            file_ips = [line.strip() for line in bl_file.read_text(encoding="utf-8").splitlines() if line.strip()]

        # Malformed lines (a typo, an old unvalidated row) are dropped
        # instead of breaking nginx -t on every edge (P4.4).
        all_ips = _valid_ips(file_ips + db_ips)
        if all_ips:
            bl_bytes = ("\n".join(all_ips) + "\n").encode("utf-8")
            bl_info = tarfile.TarInfo(name="global_blocklist.txt")
            bl_info.size = len(bl_bytes)
            bl_info.mtime = 0
            tar.addfile(bl_info, io.BytesIO(bl_bytes))

            rule_bytes = _block_rule_content().encode("utf-8")
            rule_info = tarfile.TarInfo(name="custom-000000-global-blocklist.conf")
            rule_info.size = len(rule_bytes)
            rule_info.mtime = 0
            tar.addfile(rule_info, io.BytesIO(rule_bytes))

    # Byte-identical output for identical rules: edges reload nginx whenever
    # the bundle's sha256 changes, so a timestamp here (gzip header, synthetic
    # entries) made every edge reload every SYNC_INTERVAL_SEC.
    gz = gzip.compress(tar_buf.getvalue(), mtime=0)
    if not BUNDLE_SIGNING_KEY:
        # Fail closed: an unsigned bundle would be refused by every edge anyway.
        raise HTTPException(status_code=503, detail="Bundle signing key is not configured")
    version = _bundle_version(hashlib.sha256(gz).hexdigest())
    return Response(content=gz, media_type="application/gzip", headers={
        "X-Bundle-Version": str(version),
        "X-Bundle-Signature": bundle_signature(version, gz),
        "Cache-Control": "no-store",
    })
