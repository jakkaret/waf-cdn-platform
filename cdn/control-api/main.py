import gzip
import io
import os
import sqlite3
import tarfile
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel

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
    # Build a gzip tar with rules + global blocklist assets.
    conn = db()
    rows = conn.execute("SELECT ip FROM blocklist ORDER BY created_at DESC").fetchall()
    conn.close()
    ips = [ip for (ip,) in rows if ip]
    blocklist_txt = "\n".join(ips) + ("\n" if ips else "")

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        # Custom rules from repo
        if RULES_DIR.exists():
            for p in sorted(RULES_DIR.glob("*.conf")):
                data = p.read_bytes()
                info = tarfile.TarInfo(name=p.name)
                info.size = len(data)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(data))

        # Global blocklist files
        bl_bytes = blocklist_txt.encode("utf-8")
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
