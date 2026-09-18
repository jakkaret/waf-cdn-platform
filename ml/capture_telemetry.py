"""Privacy-scoped, fail-open request telemetry for lab WAF traffic.

This module never persists the raw request body or request headers. It stores a
bounded daily JSONL file containing a body hash, redacted structured preview,
request metadata, and feature values for the allowlisted lab hosts only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlsplit

from ml.feature_engineering import extract_features_from_request


_CAPTURE_HOSTS = frozenset(
    {
        "dvwa.waf-it-kku.online",
        "juice.waf-it-kku.online",
        "vampi.waf-it-kku.online",
        "bwapp.waf-it-kku.online",
        "ryu.waf-it-kku.online",
    }
)
_CAPTURE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_SENSITIVE_KEY = re.compile(
    r"(?:pass(?:word|wd)?|token|secret|api[_-]?key|authorization|cookie|session|"
    r"credential|csrf|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = re.compile(
    r"(?P<key>password|passwd|token|secret|api[_-]?key|authorization|cookie|"
    r"session|credential|csrf|private[_-]?key|access[_-]?key)"
    r"(?P<sep>\s*[:=]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^&,\s}]+)",
    re.IGNORECASE,
)

_CAPTURE_ENABLED = os.getenv("WAF_CONTROLLED_CAPTURE_ENABLED", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
_CAPTURE_DIR = Path(
    os.getenv("WAF_CONTROLLED_CAPTURE_DIR", str(Path(__file__).with_name("telemetry")))
)
_RETENTION_DAYS = max(1, int(os.getenv("WAF_CONTROLLED_CAPTURE_RETENTION_DAYS", "7")))
_MAX_FILE_BYTES = max(64 * 1024, int(os.getenv("WAF_CONTROLLED_CAPTURE_MAX_FILE_BYTES", str(5 * 1024 * 1024))))
_MAX_BODY_BYTES = max(4 * 1024, int(os.getenv("WAF_CONTROLLED_CAPTURE_MAX_BODY_BYTES", str(64 * 1024))))
_MAX_PREVIEW_CHARS = max(256, int(os.getenv("WAF_CONTROLLED_CAPTURE_MAX_PREVIEW_CHARS", "4096")))
_WRITE_LOCK = threading.Lock()


def _sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY.search(str(key)))


def _redact_text(value: str) -> str:
    return _SENSITIVE_TEXT.sub(lambda m: f"{m.group('key')}{m.group('sep')}<REDACTED>", value)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "<REDACTED>" if _sensitive_key(str(key)) else _redact_object(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_query(uri: str) -> tuple[str, str]:
    parts = urlsplit(uri or "/")
    pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=1000):
        safe_value = "<REDACTED>" if _sensitive_key(key) else _redact_text(value[:512])
        pairs.append(f"{quote_plus(key[:128])}={quote_plus(safe_value)}")
    return parts.path[:2048] or "/", "&".join(pairs)[:4096]


def _redacted_preview(raw_body: bytes, content_type: str) -> str | None:
    if not raw_body:
        return None
    text = raw_body[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
    lower_type = (content_type or "").lower()
    try:
        if "json" in lower_type:
            parsed = json.loads(text)
            safe = json.dumps(_redact_object(parsed), ensure_ascii=False, separators=(",", ":"))
            return safe[:_MAX_PREVIEW_CHARS]
        if "application/x-www-form-urlencoded" in lower_type:
            pairs = []
            for key, value in parse_qsl(text, keep_blank_values=True, max_num_fields=1000):
                safe_value = "<REDACTED>" if _sensitive_key(key) else _redact_text(value[:512])
                pairs.append(f"{quote_plus(key[:128])}={quote_plus(safe_value)}")
            return "&".join(pairs)[:_MAX_PREVIEW_CHARS]
        if lower_type.startswith("text/") or "javascript" in lower_type:
            return _redact_text(text)[:_MAX_PREVIEW_CHARS]
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return None


def _purge_old_files(now: datetime) -> None:
    cutoff = now - timedelta(days=_RETENTION_DAYS)
    for candidate in _CAPTURE_DIR.glob("request_capture-*.jsonl"):
        try:
            if datetime.fromtimestamp(candidate.stat().st_mtime, tz=timezone.utc) < cutoff:
                candidate.unlink(missing_ok=True)
        except OSError:
            continue


def capture_request(
    *,
    host: str,
    method: str,
    uri: str,
    request_id: str,
    content_type: str,
    body: bytes,
) -> dict[str, Any]:
    """Persist privacy-scoped telemetry; all failures are intentionally fail-open."""
    normalized_host = (host or "").split(":", 1)[0].lower()
    normalized_method = (method or "GET").upper()
    if not _CAPTURE_ENABLED or normalized_host not in _CAPTURE_HOSTS:
        return {"stored": False, "reason": "capture_scope_or_switch"}
    if normalized_method not in _CAPTURE_METHODS:
        return {"stored": False, "reason": "method_not_in_scope"}

    body = body or b""
    body_truncated = len(body) > _MAX_BODY_BYTES
    captured_body = body[:_MAX_BODY_BYTES]
    path, query_redacted = _redact_query(uri)
    body_hash = hashlib.sha256(body).hexdigest()
    preview = _redacted_preview(captured_body, content_type)
    body_for_features = captured_body.decode("utf-8", errors="replace")

    try:
        features = extract_features_from_request(
            url=uri,
            method=normalized_method,
            body=body_for_features,
        )
    except Exception:
        features = {}

    now = datetime.now(timezone.utc)
    record = {
        "schema_version": 1,
        "captured_at": now.isoformat(),
        "host": normalized_host,
        "method": normalized_method,
        "path": path,
        "query_redacted": query_redacted,
        "request_id": (request_id or "")[:128],
        "content_type": (content_type or "")[:256],
        "body_length": len(body),
        "body_sha256": body_hash,
        "body_truncated": body_truncated,
        "body_preview_redacted": preview,
        "features": features,
    }
    line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    date_name = now.strftime("%Y%m%d")
    target = _CAPTURE_DIR / f"request_capture-{date_name}.jsonl"

    try:
        with _WRITE_LOCK:
            _CAPTURE_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
            _purge_old_files(now)
            current_size = target.stat().st_size if target.exists() else 0
            if current_size + len(line) > _MAX_FILE_BYTES:
                return {"stored": False, "reason": "daily_size_cap"}
            with target.open("ab") as handle:
                handle.write(line)
    except OSError:
        return {"stored": False, "reason": "storage_unavailable"}
    return {"stored": True, "bytes": len(line)}
