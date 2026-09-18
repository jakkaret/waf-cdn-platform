import gzip
import io
import os
import sqlite3
import tarfile
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from captcha_engine import captcha_access, issue_challenge, verify_challenge, ChallengeVerifyRequest
from otp_engine import otp_access, shield_access, issue_challenge_page, issue_ml_challenge, request_code, verify_code, OtpRequestPayload, OtpVerifyPayload

app = FastAPI(title="CDN Control API", version="1.0.0")

DATA_DIR = Path(os.getenv("CONTROL_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "control.db"

RULES_DIR = Path(os.getenv("CUSTOM_RULES_DIR", "/src/custom-rules"))

CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "")


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
    if not CONTROL_TOKEN or token != CONTROL_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid control token")


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
    if shield_type == "otp":
        return await issue_challenge_page(request)
    if shield_type == "ml":
        return await issue_ml_challenge(request)
    return await issue_challenge(request)

@app.post("/cdn-cgi/challenge/verify", include_in_schema=False)
async def captcha_verify_route(request: Request, payload: ChallengeVerifyRequest):
    return await verify_challenge(request, payload)

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
def get_blocklist() -> dict:
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
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")

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
        conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip.strip(),))
        conn.commit()
    finally:
        conn.close()

    return {"status": "ok", "ip": ip}


@app.get("/api/sync/bundle")
def get_bundle() -> Response:
    # Build a gzip tar with rules + global blocklist assets from RULES_DIR
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        # 1. Add all .conf and .txt files from RULES_DIR
        if RULES_DIR.exists():
            for p in sorted(RULES_DIR.glob("*")):
                if p.is_file() and (p.suffix in [".conf", ".txt", ".data"] or p.name.endswith(".conf") or p.name.endswith(".txt")):
                    data = p.read_bytes()
                    info = tarfile.TarInfo(name=p.name)
                    info.size = len(data)
                    info.mtime = int(p.stat().st_mtime)
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

        all_ips = list(dict.fromkeys(file_ips + db_ips))
        if all_ips:
            bl_bytes = ("\n".join(all_ips) + "\n").encode("utf-8")
            bl_info = tarfile.TarInfo(name="global_blocklist.txt")
            bl_info.size = len(bl_bytes)
            bl_info.mtime = int(time.time())
            tar.addfile(bl_info, io.BytesIO(bl_bytes))

            rule_bytes = _block_rule_content().encode("utf-8")
            rule_info = tarfile.TarInfo(name="custom-000000-global-blocklist.conf")
            rule_info.size = len(rule_bytes)
            rule_info.mtime = int(time.time())
            tar.addfile(rule_info, io.BytesIO(rule_bytes))

    gz = gzip.compress(tar_buf.getvalue())
    return Response(content=gz, media_type="application/gzip")
