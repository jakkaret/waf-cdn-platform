"""Edge cache purge queue.

The dashboard queues a purge here (waf-redis); control-api serves the queue
to the edges (GET /api/sync/purges, signed with BUNDLE_SIGNING_KEY like the
rule bundle) and each edge's rulesync loop deletes the matching files from its
own nginx cache (cdn/edge/entrypoint.d/99-rulesync.sh) and acknowledges how
far it got. Edges poll every few seconds, so a purge reaches every edge
without the dashboard having to reach the edges.

Keys (shared with cdn/control-api/main.py -- keep the format in step):
  cdn:purge:seq    INCR counter, the job id
  cdn:purge:jobs   sorted set, score = id, member = "<id>\\t<host>\\t<path>"
  cdn:purge:acks   hash, <edge WireGuard IP> -> "<last applied id>:<unix time>"

<path> is an exact path ("/pricing") or a prefix ending in "*" ("/static/*",
"/*" for the whole site). The edge cache key is
"http|<host>|<method>|<uri>" and nothing with a query string is cached, so a
path never carries one.
"""
from __future__ import annotations

import os
import re
import time
from typing import Dict, Optional

import redis

SEQ_KEY = "cdn:purge:seq"
JOBS_KEY = "cdn:purge:jobs"
ACKS_KEY = "cdn:purge:acks"
KEEP_JOBS = 1000

# Edge WireGuard address -> name (services/edge_tunnel.py holds the same pair).
EDGE_NAMES = {"10.88.0.2": "edge-th", "10.88.0.3": "edge-asia"}

_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
MAX_PATH = 2048


def _redis_client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        password=os.getenv("REDIS_PASSWORD") or None,
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=2,
    )


def normalize_path(path: Optional[str]) -> str:
    """"/x" (exact) or "/x*" (prefix); empty means the whole site. A query
    string or fragment is dropped (such responses are never cached)."""
    text = (path or "").strip() or "/*"
    text = text.split("#", 1)[0].split("?", 1)[0]
    if not text.startswith("/"):
        raise ValueError("path must start with /")
    if len(text) > MAX_PATH or any(ord(c) < 0x21 or ord(c) == 0x7F for c in text):
        raise ValueError("path must be a URL path without spaces or control characters")
    if "*" in text[:-1]:
        raise ValueError("* is allowed only at the end (prefix purge)")
    return text


def normalize_host(host: str) -> str:
    text = (host or "").strip().lower().rstrip(".")
    if not _HOST_RE.match(text):
        raise ValueError("host must be a domain name")
    return text


def enqueue(host: str, path: str, client=None) -> int:
    r = client or _redis_client()
    job_id = int(r.incr(SEQ_KEY))
    pipe = r.pipeline()
    pipe.zadd(JOBS_KEY, {f"{job_id}\t{host}\t{path}": job_id})
    pipe.zremrangebyrank(JOBS_KEY, 0, -(KEEP_JOBS + 1))
    pipe.execute()
    return job_id


def status(job_id: int, client=None) -> Dict[str, dict]:
    """Per edge: whether it has applied `job_id`, and when it last polled."""
    r = client or _redis_client()
    acks = r.hgetall(ACKS_KEY) or {}
    out = {}
    for ip, name in EDGE_NAMES.items():
        applied, _, at = (acks.get(ip) or "").partition(":")
        out[name] = {
            "applied": applied.isdigit() and int(applied) >= job_id,
            "last_poll": int(at) if at.isdigit() else None,
            "polling": at.isdigit() and time.time() - int(at) < 60,
        }
    return out
