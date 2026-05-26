import datetime
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query

app = FastAPI(title="CDN Purge API", version="1.0.0")

PURGE_TOKEN = os.getenv("PURGE_TOKEN", "")
CACHE_ROOTS: Dict[str, Path] = {
    "SG": Path("/cache/sg/edge"),
    "JP": Path("/cache/jp/edge"),
    "TH": Path("/cache/th/edge"),
}


def normalize_uri(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("url is required")

    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        split = urlsplit(raw_url)
        uri = split.path or "/"
    else:
        uri = raw_url if raw_url.startswith("/") else f"/{raw_url}"

    return uri


def cache_keys_for_uri(uri: str) -> List[str]:
    # Must match proxy_cache_key "$request_method|$uri"
    keys = [f"GET|{uri}", f"HEAD|{uri}"]
    return [hashlib.md5(k.encode("utf-8")).hexdigest() for k in keys]


def remove_cache_files(cache_root: Path, uri: str) -> Tuple[int, List[str]]:
    removed = 0
    removed_files: List[str] = []

    if not cache_root.exists():
        return removed, removed_files

    for digest in cache_keys_for_uri(uri):
        direct = cache_root / digest[0] / digest[1:3] / digest
        if direct.exists() and direct.is_file():
            direct.unlink(missing_ok=True)
            removed += 1
            removed_files.append(str(direct))

        # Fallback in case file layout differs
        for file_path in cache_root.rglob(digest):
            if file_path.is_file():
                file_path.unlink(missing_ok=True)
                removed += 1
                removed_files.append(str(file_path))

    return removed, removed_files


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "service": "purge-api",
        "regions": list(CACHE_ROOTS.keys()),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.post("/purge")
def purge(
    url: str = Query(..., description="URL or URI to purge, e.g. /index.php"),
    region: str = Query("ALL", description="SG,JP,TH or ALL"),
    x_purge_token: str = Header(default=""),
):
    if not PURGE_TOKEN or x_purge_token != PURGE_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid purge token")

    try:
        uri = normalize_uri(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    req_region = region.upper().strip()
    if req_region == "ALL":
        targets = CACHE_ROOTS
    else:
        if req_region not in CACHE_ROOTS:
            raise HTTPException(status_code=404, detail=f"Unknown region: {req_region}")
        targets = {req_region: CACHE_ROOTS[req_region]}

    results = []
    total_removed = 0
    for reg, root in targets.items():
        removed, files = remove_cache_files(root, uri)
        total_removed += removed
        results.append(
            {
                "region": reg,
                "cache_root": str(root),
                "removed_count": removed,
                "removed_files": files,
            }
        )

    return {
        "status": "ok",
        "uri": uri,
        "total_removed": total_removed,
        "results": results,
    }
