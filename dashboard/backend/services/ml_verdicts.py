"""Gen 3 verdicts of real traffic (ML Insights): relay buffer -> ClickHouse, and tenant-scoped reads.

nginx mirrors every request, body included, to /api/ml/capture; the ML
service scores it with Gen 3 and answers a verdict (ml/ml_api.py
score_captured: score, detectors, redacted path/query, never the body). The
relay hands each verdict to enqueue(); the worker below inserts them into
ClickHouse table ml_verdicts (created in clickhouse_service.init_db) in
batches. Nothing here blocks a request: a verdict from the inline gate of an
origin in enforce mode (/api/ml/gate, services/ml_gate.py) carries the action
the gate took ("pass", "challenge", "block"); a mirrored one carries none.

Readers always pass the tenant clause of services/tenant_service.py
(build_tenant_origin_filter, the same one the Logs page uses), which is what
keeps one origin's traffic out of another origin's view.
"""
import asyncio
import logging
import os
import re
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from services.clickhouse_service import stored_host
from services.pii_masker import SENSITIVE_KEY_NAMES, pii_masker

logger = logging.getLogger(__name__)

ENABLED = os.getenv("ML_VERDICTS_ENABLED", "true").strip().lower() not in {"0", "false", "off", "no"}
BATCH = 500
# A ClickHouse outage must not grow the backend's memory: past this, the oldest verdicts go.
MAX_BUFFER = 20000
COLUMNS = ["timestamp", "request_id", "host", "method", "path", "query", "score", "threshold",
           "is_attack", "detectors", "body_length", "feature_set", "action", "body_sample"]
# What the inline gate did; "" = log mode (mirrored, nothing enforced).
ACTIONS = ("", "pass", "challenge", "block")
HISTOGRAM_BINS = 20  # 5 points of score each
# Scores from here up, though below the model threshold, are "worth a look".
WATCH_FLOOR = 0.5
# Body kept with a verdict (2026-10-27) so an origin's Owner/Editors can read the
# payload and turn it into a rule: only from WATCH_FLOOR up, at most this many
# characters, PII and secrets masked before it is buffered (mask_body), gone with
# the row after the table TTL (7 days). Never returned by insights().
BODY_SAMPLE_MAX = 4096

_MULTIPART_SECRET = re.compile(
    rf'(?i)(name="(?:{SENSITIVE_KEY_NAMES})"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)')


def mask_body(text: str) -> str:
    """Secrets and personal data out of a body sample: the platform's PII masker
    (Thai ID, card numbers, tokens, key=value and JSON secrets, e-mail, Thai
    mobile numbers) plus the value of a sensitive multipart form field."""
    if not text:
        return ""
    text = _MULTIPART_SECRET.sub(lambda m: m.group(1) + "[MASKED]", text)
    masked, _types = pii_masker.mask_text(text)
    return masked


def body_sample(body, score) -> str:
    """The masked sample to store with a verdict of `score`, "" below WATCH_FLOOR."""
    value = _unit(score)
    if not body or value is None or value < WATCH_FLOOR:
        return ""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body[:BODY_SAMPLE_MAX * 4]).decode("utf-8", errors="replace")
    return mask_body(str(body)[:BODY_SAMPLE_MAX])[:BODY_SAMPLE_MAX]

_buffer: deque = deque(maxlen=MAX_BUFFER)


def _unit(value) -> Optional[float]:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if 0.0 <= v <= 1.0 else None


def _row(verdict: dict, body=None) -> Optional[list]:
    """One ml_verdicts row from an ML service verdict; None if it is not one.
    `body`: the request body the verdict is about (masked here, kept only from
    WATCH_FLOOR up)."""
    if not isinstance(verdict, dict):
        return None
    score = _unit(verdict.get("score"))
    if score is None:
        return None
    detectors = verdict.get("detectors") or []
    if not isinstance(detectors, list):
        detectors = []
    try:
        body_length = max(0, min(int(verdict.get("body_length") or 0), 2**32 - 1))
    except (TypeError, ValueError):
        body_length = 0
    return [
        datetime.now(timezone.utc),
        str(verdict.get("request_id") or "")[:128],
        stored_host(verdict.get("host")),
        str(verdict.get("method") or "GET").upper()[:16],
        str(verdict.get("path") or "/")[:2048],
        str(verdict.get("query") or "")[:4096],
        score,
        _unit(verdict.get("threshold")) or 0.0,
        1 if verdict.get("is_attack") is True else 0,
        [str(d)[:64] for d in detectors[:16]],
        body_length,
        str(verdict.get("feature_set") or "")[:64],
        verdict.get("action") if verdict.get("action") in ACTIONS else "",
        body_sample(body, score),
    ]


def enqueue(verdict: dict, body=None) -> bool:
    """Buffer one verdict for the next batch insert. Never raises."""
    if not ENABLED:
        return False
    try:
        row = _row(verdict, body)
    except Exception:
        logger.exception("dropping malformed ML verdict")
        return False
    if row is None:
        return False
    _buffer.append(row)
    return True


def flush_once(ch) -> int:
    """Insert up to BATCH buffered verdicts. On failure they go back to the front
    (as far as the buffer has room) to be retried next tick."""
    rows = []
    while _buffer and len(rows) < BATCH:
        rows.append(_buffer.popleft())
    if not rows:
        return 0
    try:
        ch.client.insert("ml_verdicts", rows, column_names=COLUMNS)
    except Exception:
        room = MAX_BUFFER - len(_buffer)
        _buffer.extendleft(reversed(rows[:room]))
        raise
    return len(rows)


async def ml_verdicts_worker(ch, interval: float = 2.0):
    logger.info("ml verdicts worker starting")
    while True:
        moved = 0
        try:
            if ch.connected and _buffer:
                # clickhouse calls are blocking; keep them off the loop
                moved = await asyncio.to_thread(flush_once, ch)
        except Exception:
            logger.exception("ml verdicts flush failed")
        await asyncio.sleep(0 if moved >= BATCH else interval)


def _bucket_seconds(hours: int) -> int:
    return 3600 if hours <= 48 else 6 * 3600


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty_insights(hours: int) -> dict:
    return {
        "hours": int(hours), "bucket_seconds": _bucket_seconds(hours),
        "summary": {"total": 0, "flagged": 0, "watch": 0, "hosts": 0, "last_seen": None,
                    "threshold": None, "feature_set": None, "blocked": 0, "challenged": 0},
        "histogram": [{"from": i / HISTOGRAM_BINS, "to": (i + 1) / HISTOGRAM_BINS, "count": 0, "flagged": 0}
                      for i in range(HISTOGRAM_BINS)],
        "timeline": [], "detectors": [], "requests": [],
    }


def insights(ch, scope: str, hours: int = 24, limit: int = 50, min_score: Optional[float] = None) -> dict:
    """ML Insights for the rows `scope` (a tenant clause) allows, over the last `hours`.

    `requests` lists the newest flagged requests (is_attack), or every request
    scoring at least `min_score` when it is given, each with what the WAF
    answered (access_logs status) when that row is already there.
    """
    out = empty_insights(hours)
    bucket = out["bucket_seconds"]
    where = f"({scope or '1=1'}) AND timestamp > now() - INTERVAL {{hours:UInt32}} HOUR"
    params = {"hours": int(hours), "watch": WATCH_FLOOR, "bucket": bucket, "bins": HISTOGRAM_BINS}

    total, flagged, watch, hosts, last_seen, threshold, feature_set, blocked, challenged = ch.client.query(
        "SELECT count(), countIf(is_attack = 1), countIf(is_attack = 0 AND score >= {watch:Float32}), "
        "uniqExact(host), toUnixTimestamp(max(timestamp)), argMax(threshold, timestamp), argMax(feature_set, timestamp), "
        "countIf(action = 'block'), countIf(action = 'challenge') "
        f"FROM ml_verdicts WHERE {where}",
        parameters=params,
    ).result_rows[0]
    if not total:
        return out
    out["summary"] = {
        "total": int(total), "flagged": int(flagged), "watch": int(watch), "hosts": int(hosts),
        "last_seen": _iso(last_seen), "threshold": round(float(threshold), 4), "feature_set": feature_set or None,
        "blocked": int(blocked), "challenged": int(challenged),
    }

    for b, n, f in ch.client.query(
        "SELECT least({bins:UInt8} - 1, toUInt8(floor(score * {bins:UInt8}))) AS b, count(), countIf(is_attack = 1) "
        f"FROM ml_verdicts WHERE {where} GROUP BY b ORDER BY b",
        parameters=params,
    ).result_rows:
        out["histogram"][int(b)].update(count=int(n), flagged=int(f))

    counts = {int(t): (int(n), int(f)) for t, n, f in ch.client.query(
        "SELECT intDiv(toUnixTimestamp(timestamp), {bucket:UInt32}) * {bucket:UInt32} AS t, count(), countIf(is_attack = 1) "
        f"FROM ml_verdicts WHERE {where} GROUP BY t ORDER BY t",
        parameters=params,
    ).result_rows}
    now = int(time.time())
    start = (now - int(hours) * 3600) // bucket * bucket
    out["timeline"] = [
        {"t": _iso(t), "count": counts.get(t, (0, 0))[0], "flagged": counts.get(t, (0, 0))[1]}
        for t in range(start, now + 1, bucket)
    ]

    out["detectors"] = [
        {"detector": d, "count": int(n)}
        for d, n in ch.client.query(
            f"SELECT arrayJoin(detectors) AS d, count() AS n FROM ml_verdicts WHERE {where} AND is_attack = 1 "
            "GROUP BY d ORDER BY n DESC LIMIT 12",
            parameters=params,
        ).result_rows
    ]

    params_list = {**params, "limit": int(limit)}
    if min_score is None:
        pick = "is_attack = 1"
    else:
        pick = "score >= {min_score:Float32}"
        params_list["min_score"] = float(min_score)
    rows = ch.client.query(
        "SELECT toUnixTimestamp(timestamp), request_id, host, method, path, query, score, threshold, "
        f"is_attack, detectors, body_length, action, body_sample != '' FROM ml_verdicts WHERE {where} AND {pick} "
        "ORDER BY timestamp DESC, score DESC LIMIT {limit:UInt32}",
        parameters=params_list,
    ).result_rows
    seen = _access_by_request_id(ch, scope, hours, [r[1] for r in rows if r[1]])
    out["requests"] = [
        {
            "timestamp": _iso(ts), "request_id": rid, "host": host, "method": method, "path": path,
            "query": query, "score": round(float(score), 4), "threshold": round(float(thr), 4),
            "is_attack": bool(is_attack), "detectors": list(detectors), "body_length": int(body_length),
            "action": action or None, "has_body": bool(has_body),
            **seen.get(rid, {"status_code": None, "client_ip": None, "country": None}),
        }
        for ts, rid, host, method, path, query, score, thr, is_attack, detectors, body_length, action, has_body in rows
    ]
    return out


def get_verdict(ch, scope: str, request_id: str) -> Optional[dict]:
    """One verdict, masked body sample included, if `scope` (an origin's
    host clause from tenant_service, never user text) covers its host."""
    rows = ch.client.query(
        "SELECT toUnixTimestamp(timestamp), request_id, host, method, path, query, score, threshold, is_attack, "
        f"detectors, body_length, action, body_sample FROM ml_verdicts WHERE ({scope or '1=0'}) "
        "AND request_id = {rid:String} ORDER BY timestamp DESC LIMIT 1",
        parameters={"rid": str(request_id)[:128]},
    ).result_rows
    if not rows:
        return None
    ts, rid, host, method, path, query, score, thr, is_attack, detectors, body_length, action, sample = rows[0]
    return {
        "timestamp": _iso(ts), "request_id": rid, "host": host, "method": method, "path": path, "query": query,
        "score": round(float(score), 4), "threshold": round(float(thr), 4), "is_attack": bool(is_attack),
        "detectors": list(detectors), "body_length": int(body_length), "action": action or None,
        "body_sample": sample or "",
    }


def _access_by_request_id(ch, scope: str, hours: int, request_ids: list) -> dict:
    """request_id -> what the WAF answered and who sent it, from access_logs.
    Best effort: a row the log forwarder has not written yet is simply absent."""
    if not request_ids:
        return {}
    try:
        rows = ch.client.query(
            "SELECT request_id, any(status_code), any(client_ip), any(country) FROM access_logs "
            f"WHERE ({scope or '1=1'}) AND timestamp > now() - INTERVAL {{hours:UInt32}} HOUR - INTERVAL 1 HOUR "
            "AND request_id IN {ids:Array(String)} GROUP BY request_id",
            parameters={"hours": int(hours), "ids": list(request_ids)},
        ).result_rows
    except Exception as exc:
        logger.warning("access_logs lookup for ML insights failed: %s", exc)
        return {}
    return {rid: {"status_code": int(status) if status else None, "client_ip": ip or None, "country": country or None}
            for rid, status, ip, country in rows}
