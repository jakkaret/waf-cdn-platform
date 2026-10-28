"""Per-origin ML protection: whether a Gen 3 score can change what a visitor
gets (waf.origin_ml_protection, migration 0021).

Every origin starts in "log": the mirror scores each request and ML Insights
shows it, nothing else happens. An Owner or Editor can switch the origin to
"enforce" with two bands on the 0-100 score:

    score >= block_score      403, whatever the visitor holds
    score >= challenge_score  the challenge page, unless the visitor already
                              has a CAPTCHA clearance for the host

How it reaches the WAF: this module renders one nginx map file,

    <repo>/nginx/ml-gate/hosts.map   (mounted at /etc/nginx/ml-gate/)

with a line per verified host of each enforcing origin:

    "shop.example.com" "enforce:88:95";

default.conf.template maps $host through it into $ml_gate; the njs gate
(nginx/njs/mlgate.js) passes a request with an empty $ml_gate straight to the
origin without calling ML. A host missing from the file -- the file gone, a
stale render, a host claimed by two origins -- is therefore always log mode:
nothing here can block traffic nobody switched on.

The file is rewritten after every settings change and on a timer
(ml_gate_worker), checked with `nginx -t` before nginx reloads it, and put back
as it was if the test fails.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from db import pool
from services.rule_manager import RULES_LOCK as _lock

logger = logging.getLogger(__name__)

MODES = ("log", "enforce")
DEFAULT_CHALLENGE = 88
DEFAULT_BLOCK = 95
CHALLENGE_RANGE = (50, 99)
BLOCK_RANGE = (51, 100)

REPO_DIR = Path(__file__).resolve().parents[3]
MAP_DIR = Path(os.getenv("ML_GATE_MAP_DIR", str(REPO_DIR / "nginx" / "ml-gate")))
MAP_FILE = "hosts.map"
MAP_HEADER = "# managed-by: services/ml_gate.py -- per-host ML gate policy, do not edit\n"

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_POLICY_RE = re.compile(r"^enforce:(\d{1,3}):(\d{1,3})$")

Policy = Tuple[Optional[int], int]  # (challenge_score or None, block_score)


class MlProtectionError(ValueError):
    pass


# ---- the decision -----------------------------------------------------------

def policy_value(challenge_score: Optional[int], block_score: int) -> str:
    """The map value nginx forwards to the gate relay as X-ML-Gate."""
    return f"enforce:{challenge_score or 0}:{block_score}"


def parse_policy(raw: Any) -> Optional[Policy]:
    """X-ML-Gate as nginx sent it, or None for anything that is not a valid
    enforce policy (empty = log mode). A malformed value never enforces."""
    m = _POLICY_RE.match(str(raw or "").strip())
    if not m:
        return None
    challenge, block = int(m.group(1)), int(m.group(2))
    if not BLOCK_RANGE[0] <= block <= BLOCK_RANGE[1]:
        return None
    if challenge == 0:
        return None, block
    if not CHALLENGE_RANGE[0] <= challenge <= CHALLENGE_RANGE[1] or challenge >= block:
        return None
    return challenge, block


def decide(score: float, policy: Policy) -> str:
    """"block" | "challenge" | "pass" for a 0-1 model score."""
    challenge, block = policy
    points = round(float(score) * 100, 4)
    if points >= block:
        return "block"
    if challenge is not None and points >= challenge:
        return "challenge"
    return "pass"


# ---- the action, for the access log -----------------------------------------
#
# The access log row of a request comes from the edge (api/cdn.py's ingest), a
# few seconds after the gate answered it, with the same request id: nginx sends
# the edge's X-Request-ID as X-Original-Request-ID ($waf_request_id). Without
# this the row of an ML block reads like a ModSecurity one (WAF-CRS). In memory,
# one backend process: a restart only loses the labels of the last few seconds.

ACTION_TTL_SECONDS = 900
ACTIONS_MAX = 50_000
_actions: "OrderedDict[str, Tuple[float, str]]" = OrderedDict()
_actions_lock = threading.Lock()


def remember_action(request_id: Any, action: str, now: Optional[float] = None) -> None:
    """Keep a "block" / "challenge" answer until the edge's log row arrives."""
    rid = str(request_id or "").strip()[:128]
    if not rid or action not in ("block", "challenge"):
        return
    now = time.monotonic() if now is None else now
    with _actions_lock:
        _actions[rid] = (now, action)
        _actions.move_to_end(rid)
        while _actions and (len(_actions) > ACTIONS_MAX
                            or next(iter(_actions.values()))[0] < now - ACTION_TTL_SECONDS):
            _actions.popitem(last=False)


def recalled_action(request_id: Any, now: Optional[float] = None) -> Optional[str]:
    """"block" / "challenge" if the gate answered this request, else None."""
    rid = str(request_id or "").strip()[:128]
    if not rid:
        return None
    now = time.monotonic() if now is None else now
    with _actions_lock:
        hit = _actions.get(rid)
    if hit is None or hit[0] < now - ACTION_TTL_SECONDS:
        return None
    return hit[1]


# ---- settings ---------------------------------------------------------------

def _defaults(origin_id: str) -> Dict[str, Any]:
    return {"origin_id": origin_id, "mode": "log", "challenge_score": DEFAULT_CHALLENGE,
            "block_score": DEFAULT_BLOCK, "updated_by": "", "updated_at": None}


def _row(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"origin_id": str(r["origin_id"]), "mode": r["mode"], "challenge_score": r["challenge_score"],
            "block_score": r["block_score"], "updated_by": r["updated_by"],
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None}


def get_settings(origin_id: str) -> Dict[str, Any]:
    r = pool.q1("SELECT * FROM origin_ml_protection WHERE origin_id = %s::uuid", (origin_id,))
    return _row(r) if r else _defaults(origin_id)


def validate(mode: str, challenge_score: Optional[int], block_score: int) -> Tuple[str, Optional[int], int]:
    mode = str(mode or "").strip().lower()
    if mode not in MODES:
        raise MlProtectionError("mode must be log or enforce")
    try:
        block_score = int(block_score)
        challenge_score = None if challenge_score is None else int(challenge_score)
    except (TypeError, ValueError):
        raise MlProtectionError("scores must be whole numbers")
    if not BLOCK_RANGE[0] <= block_score <= BLOCK_RANGE[1]:
        raise MlProtectionError(f"block score must be {BLOCK_RANGE[0]}-{BLOCK_RANGE[1]}")
    if challenge_score is not None:
        if not CHALLENGE_RANGE[0] <= challenge_score <= CHALLENGE_RANGE[1]:
            raise MlProtectionError(f"challenge score must be {CHALLENGE_RANGE[0]}-{CHALLENGE_RANGE[1]}")
        if challenge_score >= block_score:
            raise MlProtectionError("challenge score must be lower than the block score")
    return mode, challenge_score, block_score


def save_settings(origin_id: str, mode: str, challenge_score: Optional[int], block_score: int,
                  by: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(previous, saved). Runs on the caller's transaction when there is one."""
    mode, challenge_score, block_score = validate(mode, challenge_score, block_score)
    previous = get_settings(origin_id)
    r = pool.q1(
        "INSERT INTO origin_ml_protection (origin_id, mode, challenge_score, block_score, updated_by, updated_at) "
        "VALUES (%s, %s, %s, %s, %s, now()) ON CONFLICT (origin_id) DO UPDATE SET mode = EXCLUDED.mode, "
        "challenge_score = EXCLUDED.challenge_score, block_score = EXCLUDED.block_score, "
        "updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at RETURNING *",
        (origin_id, mode, challenge_score, block_score, by or ""))
    return previous, _row(r)


def enforcing_policies() -> Dict[str, str]:
    """origin_id -> map value for every origin in enforce mode."""
    return {str(r["origin_id"]): policy_value(r["challenge_score"], r["block_score"])
            for r in pool.q("SELECT origin_id, challenge_score, block_score FROM origin_ml_protection "
                            "WHERE mode = 'enforce'")}


# ---- the nginx map ----------------------------------------------------------

def render_map(hostmap: Dict[str, str], policies: Dict[str, str]) -> str:
    """hostmap: host -> origin_id (services/shield_sync.desired_hostmap: only
    verified hosts of active origins, a host claimed twice left out)."""
    lines = [MAP_HEADER]
    for host in sorted(hostmap):
        value = policies.get(str(hostmap[host]))
        if value is None or not _HOST_RE.match(host) or not _POLICY_RE.match(value):
            continue
        lines.append(f'"{host}" "{value}";\n')
    return "".join(lines)


def map_path() -> Path:
    return MAP_DIR / MAP_FILE


def read_map() -> Optional[str]:
    try:
        return map_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def hosts_in_map(text: Optional[str]) -> Dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r'^"([^"]+)" "([^"]+)";$', line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _write(text: Optional[str]) -> None:
    path = map_path()
    if text is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


_rule_manager = None


def _rm():
    global _rule_manager
    if _rule_manager is None:
        from services.rule_manager import RuleManager
        _rule_manager = RuleManager()
    return _rule_manager


_state: Dict[str, Any] = {"last_error": None, "applied_at": None}


def sync(db) -> bool:
    """Make hosts.map match the database, `nginx -t`, reload. Puts the previous
    file back when the test or the reload fails. Returns whether it changed.
    Blocking: call from a worker thread."""
    from services.shield_sync import desired_hostmap
    with _lock:
        text = render_map(desired_hostmap(db), enforcing_policies())
        old = read_map()
        if old == text:
            return False
        _write(text)
        try:
            _rm().test_nginx()
            _rm().reload_nginx()
        except Exception as exc:
            _write(old)
            _state["last_error"] = str(exc)[:300]
            raise
        _state.update(last_error=None, applied_at=datetime.now(timezone.utc).isoformat())
        logger.info("ml gate map: %d enforcing host(s)", len(hosts_in_map(text)))
        return True


def sync_quietly(db) -> None:
    try:
        sync(db)
    except Exception as exc:
        logger.warning("ml gate map not applied (the worker retries): %s", exc)


def status() -> Dict[str, Any]:
    return dict(_state)


async def ml_gate_worker(db, interval_seconds: int = 60) -> None:
    """Re-renders the map on a timer, so a newly verified or removed host, an
    archived origin or a missed reload is picked up within one interval."""
    import asyncio
    while True:
        await asyncio.to_thread(sync_quietly, db)
        await asyncio.sleep(interval_seconds)


# ---- what a setting would have done ----------------------------------------

def preview(ch, scope: str, challenge_score: Optional[int], block_score: int, hours: int = 168) -> Dict[str, Any]:
    """Counts of the origin's scored requests in the last `hours` that the
    bands would have challenged or blocked, plus the newest would-be blocks.
    `scope` is the tenant clause of api/ml._insights_scope (never user text)."""
    where = f"timestamp >= now() - INTERVAL {{hours:UInt32}} HOUR AND ({scope or '1=1'})"
    params = {"hours": int(hours), "block": float(block_score), "challenge": float(challenge_score or 101)}
    points = "round(toFloat64(score) * 100, 4)"
    total, blocked, challenged, first = ch.client.query(
        f"SELECT count(), countIf({points} >= {{block:Float64}}), "
        f"countIf({points} >= {{challenge:Float64}} AND {points} < {{block:Float64}}), "
        f"toUnixTimestamp(min(timestamp)) FROM ml_verdicts WHERE {where}", parameters=params,
    ).result_rows[0]
    examples = []
    if blocked:
        examples = [
            {"timestamp": int(ts), "host": host, "method": method, "path": path, "score": round(float(score), 4)}
            for ts, host, method, path, score in ch.client.query(
                f"SELECT toUnixTimestamp(timestamp), host, method, path, score FROM ml_verdicts "
                f"WHERE {where} AND {points} >= {{block:Float64}} ORDER BY timestamp DESC LIMIT 5",
                parameters=params,
            ).result_rows
        ]
    return {
        "hours": int(hours), "total": int(total), "would_block": int(blocked),
        "would_challenge": int(challenged) if challenge_score else 0,
        "since": int(first) if total else None, "examples": examples,
    }
