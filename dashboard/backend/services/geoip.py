"""Client-IP -> ISO 3166-1 alpha-2 country code.

access_logs.country used to be filled in with a guess: log ingestion
defaulted a missing value to "TH" (services/clickhouse_service.py), and the
CDN path derived it from the *edge node's* region, not from the client at
all (services/cdn_log_forward.py). The result was that 100% of rows said TH
and the dashboard's Geographic Distribution panel showed one country no
matter who was actually connecting -- a fabricated categorical value, the
same class of bug resolve_edge_node() already documents for edge_node.

This resolves the country from the real client IP against a local MaxMind-
format (.mmdb) database. Two databases work interchangeably because they
share the format and the country.iso_code record shape:

  * DB-IP Lite Country (default; free, no account, CC BY 4.0 -- the
    dashboard shows the required attribution next to the panel).
  * MaxMind GeoLite2-Country (needs an account + license key). Point
    GEOIP_DB_PATH at it to switch; nothing else changes.

Fail-soft on purpose: a missing database, an unreadable file, a private or
malformed address all return "" (unknown). Log ingestion must never fail
because a lookup did, and "" is honest where "TH" was not -- analytics
already excludes country = '' from the country breakdown.
"""
import ipaddress
import logging
import os
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "geoip" / "dbip-country-lite.mmdb"

_lock = threading.Lock()
_reader = None
_reader_path: Optional[str] = None
_load_failed_for: Optional[str] = None


def db_path() -> str:
    return os.getenv("GEOIP_DB_PATH") or str(_DEFAULT_DB_PATH)


def _get_reader():
    """Open the database once and reuse it. maxminddb's Reader is safe to
    share across threads, which matters here: ClickHouse row building runs
    inside asyncio.to_thread worker threads."""
    global _reader, _reader_path, _load_failed_for
    path = db_path()
    if _reader is not None and _reader_path == path:
        return _reader
    if _load_failed_for == path:
        return None
    with _lock:
        if _reader is not None and _reader_path == path:
            return _reader
        try:
            import maxminddb

            _reader = maxminddb.open_database(path)
            _reader_path = path
            _load_failed_for = None
            logger.info("geoip: loaded %s", path)
        except Exception as exc:
            # Remember the failure so a missing file costs one log line, not
            # one per ingested request.
            _reader = None
            _load_failed_for = path
            logger.warning("geoip: database unavailable at %s (%s); country will be blank", path, exc)
        return _reader


def country_code(ip) -> str:
    """ISO alpha-2 code for a public IP, or "" when it cannot be determined."""
    text = str(ip or "").strip()
    if not text:
        return ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    # Private, loopback, link-local, etc. have no country. Skipping them also
    # keeps docker-internal and edge-to-Main hops out of the country stats.
    if not addr.is_global:
        return ""
    reader = _get_reader()
    if reader is None:
        return ""
    try:
        record = reader.get(text)
    except Exception:
        return ""
    if not isinstance(record, dict):
        return ""
    code = str((record.get("country") or {}).get("iso_code") or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else ""


def flag_emoji(code: str) -> str:
    """Regional-indicator flag for an alpha-2 code; a globe for anything else."""
    code = str(code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "\U0001F310"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def reset_for_tests() -> None:
    global _reader, _reader_path, _load_failed_for
    with _lock:
        _reader = None
        _reader_path = None
        _load_failed_for = None
