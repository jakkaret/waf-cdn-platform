#!/usr/bin/env python3
"""Download / refresh the DB-IP Lite Country database used by services/geoip.py.

DB-IP publishes a new file each month and keeps the previous ones, so this
tries the current month first and falls back to the previous one (a run on
the 1st, before that month's file exists, must not fail). The new file is
verified by opening it and resolving a known address before it replaces the
live database, and the replace is a rename, so a half-downloaded or corrupt
file can never leave the dashboard without a working database.

    python scripts/update_geoip.py

Data (c) DB-IP.com, CC BY 4.0 -- https://db-ip.com. Attribution is shown on
the dashboard's Geographic Distribution panel.

Run monthly, e.g. /etc/cron.d/waf-geoip:
    17 4 5 * * root cd /root/waf_project/dashboard/backend && .venv/bin/python scripts/update_geoip.py
"""
import gzip
import os
import shutil
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import geoip  # noqa: E402

URL = "https://download.db-ip.com/free/dbip-country-lite-{ym}.mmdb.gz"
# 8.8.8.8 is Google's resolver and has been US-registered for years; if the
# downloaded file cannot place it in a real country the file is not usable.
PROBE_IP = "8.8.8.8"


def _months():
    today = date.today()
    yield f"{today.year:04d}-{today.month:02d}"
    prev_year, prev_month = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    yield f"{prev_year:04d}-{prev_month:02d}"


def _download(ym: str, dest_gz: Path) -> bool:
    url = URL.format(ym=ym)
    # download.db-ip.com answers the default "Python-urllib" User-Agent with
    # 403 (a HEAD request without it succeeds, which makes this look like an
    # availability problem rather than a header one). Identify the tool
    # honestly instead.
    request = urllib.request.Request(url, headers={"User-Agent": "waf-geoip-updater/1.0 (+https://waf-it-kku.online)"})
    try:
        with urllib.request.urlopen(request, timeout=60) as resp, open(dest_gz, "wb") as out:
            shutil.copyfileobj(resp, out)
        return True
    except Exception as exc:
        print(f"  {ym}: not available ({exc})")
        return False


def main() -> int:
    target = Path(geoip.db_path())
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        tmp_dir = Path(tmp)
        gz_path = tmp_dir / "download.mmdb.gz"
        mmdb_path = tmp_dir / "new.mmdb"

        chosen = None
        for ym in _months():
            print(f"trying {ym} ...")
            if _download(ym, gz_path):
                chosen = ym
                break
        if not chosen:
            print("ERROR: no database could be downloaded; existing file (if any) left untouched")
            return 1

        with gzip.open(gz_path, "rb") as src, open(mmdb_path, "wb") as dst:
            shutil.copyfileobj(src, dst)

        import maxminddb

        with maxminddb.open_database(str(mmdb_path)) as reader:
            record = reader.get(PROBE_IP) or {}
            code = (record.get("country") or {}).get("iso_code")
        if not code:
            print(f"ERROR: downloaded file could not resolve {PROBE_IP}; not installing it")
            return 1

        os.replace(mmdb_path, target)
        print(f"installed DB-IP Lite Country {chosen} -> {target} ({target.stat().st_size // 1024} KiB); {PROBE_IP} -> {code}")

    geoip.reset_for_tests()
    return 0


if __name__ == "__main__":
    sys.exit(main())
