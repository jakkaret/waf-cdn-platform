"""What attackers did inside the honeypot (deception layer), told as sessions.

Every deceived request becomes one row in ClickHouse ``honeypot_events``:
who (an actor id from host + IP + User-Agent, the IP, the tool its
User-Agent or path gives away), what it asked for, which stage of an attack
that is, and what it handed us (login attempts, an uploaded file, a
honeytoken coming back). Sessions are built at read time: one actor's events
with no gap longer than SESSION_GAP_SECONDS.

What is kept, and what is not (PDPA):
- passwords are never stored: an HMAC under the deception key, the length,
  and whether it is a well-known weak password;
- usernames are masked (e-mail local part cut to its first letter) plus an
  HMAC, so repeated tries of one name can be counted;
- a body sample (masked by ml_verdicts.mask_body, at most BODY_SAMPLE_CHARS)
  lives BODY_TTL_DAYS; the rest of the row lives EVENT_TTL_DAYS;
- an uploaded file: name, size, type and SHA-256 only, never its bytes.

Honeytokens are per site (deception_content), not per visitor, so a replay is
linked to every earlier session on that site that was served the same token.
"""
from __future__ import annotations

import datetime as dt
import email.parser
import email.policy
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from services import deception_content

logger = logging.getLogger("waf.honeypot")

SESSION_GAP_SECONDS = 1800
EVENT_TTL_DAYS = 90
BODY_TTL_DAYS = 7
BODY_SAMPLE_CHARS = 4096

# Ordered: a session is as far as its furthest event got.
STAGES = ("recon", "loot", "exploit", "credential_use", "persistence")
STAGE_RANK = {s: i for i, s in enumerate(STAGES)}
# Stages that are pushed to the site's team at once (the rest go into the
# daily digest): someone using a secret we planted, or dropping a file.
ALERT_STAGES = ("credential_use", "persistence")

# MITRE ATT&CK techniques the stages correspond to, for the timeline.
STAGE_ATTACK = {
    "recon": ("T1595", "Active Scanning"),
    "loot": ("T1552", "Unsecured Credentials"),
    "exploit": ("T1190", "Exploit Public-Facing Application"),
    "credential_use": ("T1078", "Valid Accounts"),
    "persistence": ("T1505.003", "Server Software Component: Web Shell"),
}

# deception_service template id -> the stage that answer represents.
_TEMPLATE_STAGE = {
    "sensitive_file": "loot",
    "path_traversal": "loot",
    "ssrf": "loot",
    "sql_injection": "exploit",
    "command_injection": "exploit",
    "xss": "exploit",
    "admin_panel": "recon",
    "honeytoken": "credential_use",
}

# Tools by User-Agent first; scanners that send a browser UA are caught by
# the path they probe for, below.
_TOOLS_UA = [
    ("sqlmap", r"sqlmap"), ("Nuclei", r"nuclei|projectdiscovery"), ("WPScan", r"wpscan"),
    ("Nikto", r"nikto"), ("gobuster", r"gobuster"), ("ffuf", r"\bffuf\b"), ("feroxbuster", r"feroxbuster"),
    ("dirsearch", r"dirsearch"), ("DirBuster", r"dirbuster"), ("wfuzz", r"wfuzz"), ("Hydra", r"hydra"),
    ("Nmap", r"nmap"), ("masscan", r"masscan"), ("ZGrab", r"zgrab"), ("Acunetix", r"acunetix"),
    ("Burp Suite", r"burp"), ("OWASP ZAP", r"\bzap\b|zaproxy"), ("Censys", r"censys"),
    ("Shodan", r"shodan"), ("Go client", r"go-http-client"), ("python-requests", r"python-requests"),
    ("Python", r"python-urllib|aiohttp|httpx"), ("curl", r"^curl/"), ("Wget", r"^wget/"),
    ("Java client", r"^java/|okhttp|apache-httpclient"), ("Headless browser", r"headlesschrome|phantomjs"),
]
_TOOLS_UA_RE = [(name, re.compile(rx, re.I)) for name, rx in _TOOLS_UA]
_BROWSER_RE = re.compile(r"mozilla/5\.0.*(chrome|firefox|safari|edg)/", re.I)

# Weak passwords people (and wordlists) try first. Only membership is kept.
_COMMON_PASSWORDS = frozenset("""
123456 123456789 12345678 12345 1234567 1234567890 1234 qwerty password password1 password123 admin admin123
administrator root toor 111111 000000 123123 abc123 letmein welcome welcome1 iloveyou monkey dragon sunshine
princess football baseball master shadow qwerty123 qwertyuiop 1q2w3e4r 1qaz2wsx zaq12wsx passw0rd p@ssw0rd
p@ssword changeme secret test test123 guest default user pass 654321 666666 888888 987654321 superman
wordpress wp-admin admin@123 adminadmin 112233 121212 7777777 asdfgh asdf1234 summer2024 winter2024
""".split())

_USER_FIELDS = ("log", "username", "user", "user_login", "login", "email", "uname", "user_name", "usr", "account")
_PASS_FIELDS = ("pwd", "password", "pass", "passwd", "user_pass", "pw", "pswd", "secret")


# ------------------------------------------------------------------ identity

def _key() -> bytes:
    return deception_content._key()


def _mac(kind: str, value: str, n: int = 24) -> str:
    return hmac.new(_key(), f"{kind}|{value}".encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:n]


def actor_id(host: str, ip: str, user_agent: str) -> str:
    """Stable id for one visitor on one site: same host, IP and User-Agent."""
    return _mac("actor", f"{deception_content.normalize_host(host)}|{ip}|{(user_agent or '')[:256]}", 16)


def tool_for(user_agent: str, path: str = "") -> str:
    ua = (user_agent or "").strip()
    for name, rx in _TOOLS_UA_RE:
        if rx.search(ua):
            return name
    p = (path or "").lower()
    if "/wp-json/wp/v2/users" in p or "/xmlrpc.php" in p:
        return "WordPress scanner"
    if not ua:
        return "No User-Agent"
    if _BROWSER_RE.search(ua):
        return "Browser"
    return "Other"


def stage_for(template_id: str, method: str = "GET", login: bool = False, upload: bool = False,
              replayed: bool = False) -> str:
    if upload:
        return "persistence"
    if replayed or template_id == "honeytoken":
        return "credential_use"
    if login:
        return "exploit"
    stage = _TEMPLATE_STAGE.get(template_id, "recon")
    if template_id == "admin_panel" and (method or "").upper() == "POST":
        return "exploit"
    return stage


# ------------------------------------------------------------------ what a request handed us

def _form_fields(body: str, content_type: str) -> Dict[str, str]:
    ct = (content_type or "").lower()
    text = (body or "")[:16384]
    if "json" in ct or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return {}
        if isinstance(data, dict):
            return {str(k).lower(): str(v) for k, v in data.items() if isinstance(v, (str, int, float))}
        return {}
    if "multipart/" in ct:
        return {}
    try:
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        return {}
    return {k.lower(): v for k, v in pairs}


def mask_user(name: str) -> str:
    name = (name or "").strip()[:128]
    if not name:
        return ""
    if "@" in name:
        local, _, domain = name.partition("@")
        return f"{local[:1]}***@{domain}"
    if len(name) <= 3:
        return name[:1] + "**"
    return name[:2] + "*" * min(len(name) - 2, 6)


def extract_login(body: str, content_type: str = "") -> Optional[Dict[str, Any]]:
    """A login attempt in a form or JSON body, without keeping the password."""
    fields = _form_fields(body, content_type)
    if not fields:
        return None
    user = next((fields[k] for k in _USER_FIELDS if fields.get(k)), "")
    password = next((fields[k] for k in _PASS_FIELDS if k in fields), None)
    if password is None:
        return None
    return {
        "user_masked": mask_user(user),
        "user_hash": _mac("user", user.strip().lower(), 16) if user else "",
        "pass_hash": _mac("password", password, 24),
        "pass_len": min(len(password), 255),
        "pass_common": password.strip().lower() in _COMMON_PASSWORDS,
    }


def extract_upload(raw: bytes, content_type: str = "") -> Optional[Dict[str, Any]]:
    """The first file in a multipart body: name, size, type, SHA-256."""
    if not raw or "multipart/form-data" not in (content_type or "").lower():
        return None
    try:
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + content_type.encode("latin-1", "replace") + b"\r\n\r\n" + raw)
    except Exception:  # noqa: BLE001 - attacker-shaped input
        return None
    for part in msg.iter_parts() if msg.is_multipart() else []:
        filename = part.get_filename()
        if not filename:
            continue
        data = part.get_payload(decode=True) or b""
        return {
            "name": re.sub(r"[\x00-\x1f]", "", filename)[:200],
            "size": len(data),
            "type": (part.get_content_type() or "")[:100],
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return None


def tokens_in(site: "deception_content.Site", text: str) -> List[str]:
    """Kinds of this site's honeytokens that appear in `text` (a response)."""
    if not text or not site.tokens:
        return []
    return sorted(k for k, v in site.tokens.items() if v and v in text)


# ------------------------------------------------------------------ attribution

_HOST_CACHE: Dict[str, Any] = {"at": 0.0, "map": {}}
_HOST_TTL = 60.0


def origin_for_host(host: str) -> str:
    """Verified hostname -> origin id ("" when unknown), cached for a minute."""
    h = deception_content.normalize_host(host)
    if not h:
        return ""
    now = time.monotonic()
    if now - _HOST_CACHE["at"] > _HOST_TTL:
        try:
            from services.site_alerts import host_origins
            _HOST_CACHE["map"] = host_origins()
        except Exception as exc:  # noqa: BLE001 - attribution is best effort
            logger.warning("honeypot: host map unavailable: %s", exc)
        _HOST_CACHE["at"] = now
    return _HOST_CACHE["map"].get(h, "")


def edge_for_peer(peer: str) -> str:
    """The edge an X-Edge-Peer address belongs to; "unknown" otherwise."""
    from services.log_forward import _EDGE_IP_TO_NODE
    p = (peer or "").strip()
    if not p:
        return "unknown"
    return _EDGE_IP_TO_NODE.get(p, "main")


# ------------------------------------------------------------------ the event

def build_event(*, request_id: str, host: str, client_ip: str, user_agent: str, method: str, uri: str,
                referer: str, content_type: str, body: str, raw_body: bytes, template_id: str,
                category: str, rule_id: str, response_body: str, delay_seconds: float, edge_peer: str,
                now: Optional[float] = None) -> Dict[str, Any]:
    """One honeypot_events row. Pure: every lookup it needs is cached or local."""
    from services.ml_verdicts import mask_body
    from services.pii_masker import pii_masker

    site = deception_content.site_for(host)
    path, _, query = (uri or "/").partition("?")
    login = extract_login(body, content_type) if (method or "").upper() in ("POST", "PUT", "PATCH") else None
    upload = extract_upload(raw_body, content_type)
    replayed = ""
    if template_id == "honeytoken":
        corpus = " ".join([uri or "", body or ""])
        replayed = deception_content.find_honeytoken(site, corpus) or "unknown"
    stage = stage_for(template_id, method, bool(login), bool(upload), bool(replayed))
    masked_path, _ = pii_masker.mask_text(path[:2048])
    masked_query, _ = pii_masker.mask_text(query[:2048]) if query else ("", [])
    sample = ""
    if body and not upload:
        sample = mask_body(body[:BODY_SAMPLE_CHARS * 2])[:BODY_SAMPLE_CHARS]
    ts = now if now is not None else time.time()
    host_n = deception_content.normalize_host(host)
    return {
        "timestamp": dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(tzinfo=None),
        "request_id": str(request_id or "")[:64],
        "origin_id": origin_for_host(host_n),
        "host": host_n,
        "edge_node": edge_for_peer(edge_peer),
        "client_ip": (client_ip or "").split(",")[0].strip()[:64],
        "user_agent": (user_agent or "")[:256],
        "actor_id": actor_id(host_n, client_ip, user_agent),
        "tool": tool_for(user_agent, path),
        "method": (method or "GET").upper()[:16],
        "path": masked_path,
        "query": masked_query,
        "referer": (referer or "")[:512],
        "template": template_id or "",
        "category": category or "",
        "stage": stage,
        "rule_id": str(rule_id or "")[:32],
        "delay_ms": int(max(0.0, delay_seconds or 0.0) * 1000),
        "body_length": len(raw_body or b"") or len(body or ""),
        "body_sample": sample,
        "login_user": (login or {}).get("user_masked", ""),
        "login_user_hash": (login or {}).get("user_hash", ""),
        "login_pass_hash": (login or {}).get("pass_hash", ""),
        "login_pass_len": int((login or {}).get("pass_len", 0)),
        "login_pass_common": 1 if (login or {}).get("pass_common") else 0,
        "upload_name": (upload or {}).get("name", ""),
        "upload_size": int((upload or {}).get("size", 0)),
        "upload_type": (upload or {}).get("type", ""),
        "upload_sha256": (upload or {}).get("sha256", ""),
        "tokens_issued": tokens_in(site, response_body) if host_n else [],
        "token_replayed": replayed,
    }


# ------------------------------------------------------------------ storage

COLUMNS = [
    "timestamp", "request_id", "origin_id", "host", "edge_node", "client_ip", "user_agent", "actor_id", "tool",
    "method", "path", "query", "referer", "template", "category", "stage", "rule_id", "delay_ms",
    "body_length", "body_sample", "login_user", "login_user_hash", "login_pass_hash", "login_pass_len",
    "login_pass_common", "upload_name", "upload_size", "upload_type", "upload_sha256", "tokens_issued",
    "token_replayed",
]

CREATE_TABLE = f"""
CREATE TABLE IF NOT EXISTS honeypot_events (
    timestamp DateTime,
    request_id String,
    origin_id String,
    host String,
    edge_node LowCardinality(String),
    client_ip String,
    user_agent String,
    actor_id String,
    tool LowCardinality(String),
    method LowCardinality(String),
    path String,
    query String,
    referer String,
    template LowCardinality(String),
    category LowCardinality(String),
    stage LowCardinality(String),
    rule_id String,
    delay_ms UInt32,
    body_length UInt32,
    body_sample String TTL timestamp + INTERVAL {BODY_TTL_DAYS} DAY,
    login_user String,
    login_user_hash String,
    login_pass_hash String,
    login_pass_len UInt8,
    login_pass_common UInt8,
    upload_name String,
    upload_size UInt32,
    upload_type String,
    upload_sha256 String,
    tokens_issued Array(LowCardinality(String)),
    token_replayed LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (origin_id, timestamp)
TTL timestamp + INTERVAL {EVENT_TTL_DAYS} DAY
"""

_CH = None
_READ_LOCK = threading.Lock()


def clickhouse():
    """Shared read client, made on first use (tests replace it)."""
    global _CH
    if _CH is None:
        from services.clickhouse_service import ClickHouseService
        _CH = ClickHouseService()
    return _CH


def store_event(ch, event: Dict[str, Any]) -> bool:
    """Insert one row with the caller's client (deception logging holds its lock)."""
    if not ch or not getattr(ch, "connected", False) or not getattr(ch, "client", None):
        return False
    try:
        ch.client.insert("honeypot_events", [[event[c] for c in COLUMNS]], column_names=COLUMNS)
        return True
    except Exception as exc:  # noqa: BLE001 - logging must never break the response
        logger.warning("honeypot_events insert failed: %s", exc)
        return False


def fetch_events(origin_id: str, since: dt.datetime, until: Optional[dt.datetime] = None,
                 limit: int = 20000) -> List[Dict[str, Any]]:
    """One origin's events in a window, oldest first; past `limit`, the
    newest are kept. [] when the store is down."""
    ch = clickhouse()
    if not getattr(ch, "connected", False) or not getattr(ch, "client", None) or not origin_id:
        return []
    until = until or dt.datetime.utcnow() + dt.timedelta(minutes=1)
    with _READ_LOCK:
        res = ch.client.query(
            f"SELECT {', '.join(COLUMNS)} FROM honeypot_events "
            "WHERE origin_id = {o:String} AND timestamp >= {s:DateTime} AND timestamp < {u:DateTime} "
            "ORDER BY timestamp DESC LIMIT {n:UInt32}",
            parameters={"o": origin_id, "s": since, "u": until, "n": limit},
        )
    return [dict(zip(COLUMNS, row)) for row in reversed(res.result_rows)]


# ------------------------------------------------------------------ sessions

def _ts(e: Dict[str, Any]) -> float:
    t = e["timestamp"]
    if isinstance(t, (int, float)):
        return float(t)
    return t.replace(tzinfo=dt.timezone.utc).timestamp() if t.tzinfo is None else t.timestamp()


def session_id(actor: str, first_ts: float) -> str:
    return f"{actor}-{int(first_ts)}"


def sessionize(events: Iterable[Dict[str, Any]], gap: int = SESSION_GAP_SECONDS) -> List[Dict[str, Any]]:
    """Group events (any order) into sessions: one actor, no gap over `gap`
    seconds. Each session keeps its events oldest first. A replay of a
    honeytoken is linked to the earlier sessions that were served it."""
    by_actor: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        by_actor.setdefault(e["actor_id"], []).append(e)
    sessions: List[Dict[str, Any]] = []
    for actor, evs in by_actor.items():
        evs.sort(key=_ts)
        current: List[Dict[str, Any]] = []
        for e in evs:
            if current and _ts(e) - _ts(current[-1]) > gap:
                sessions.append(_summarize(actor, current))
                current = []
            current.append(e)
        if current:
            sessions.append(_summarize(actor, current))
    sessions.sort(key=lambda s: s["first_seen"])
    # Link replays to the sessions that received the token.
    for s in sessions:
        for kind in s["tokens_replayed"]:
            sources = [o["id"] for o in sessions
                       if o is not s and o["first_seen"] <= s["last_seen"] and kind in o["tokens_issued"]]
            s["linked_from"] = sorted(set(s.get("linked_from", []) + sources))
    sessions.sort(key=lambda s: s["last_seen"], reverse=True)
    return sessions


def _summarize(actor: str, evs: List[Dict[str, Any]]) -> Dict[str, Any]:
    stages = [e["stage"] for e in evs if e.get("stage") in STAGE_RANK]
    max_stage = max(stages, key=lambda s: STAGE_RANK[s]) if stages else "recon"
    tools = [e["tool"] for e in evs if e.get("tool")]
    tool = max(set(tools), key=tools.count) if tools else "Other"
    issued = sorted({k for e in evs for k in (e.get("tokens_issued") or [])})
    replayed = sorted({e["token_replayed"] for e in evs if e.get("token_replayed")})
    first, last = _ts(evs[0]), _ts(evs[-1])
    return {
        "id": session_id(actor, first),
        "actor_id": actor,
        "first_seen": first,
        "last_seen": last,
        "duration_seconds": int(last - first),
        "events": len(evs),
        "ips": sorted({e["client_ip"] for e in evs if e.get("client_ip")}),
        "user_agent": evs[0].get("user_agent", ""),
        "tool": tool,
        "edge_nodes": sorted({e.get("edge_node") or "unknown" for e in evs}),
        "max_stage": max_stage,
        "stages": [s for s in STAGES if s in set(stages)],
        "categories": sorted({e["category"] for e in evs if e.get("category")}),
        "login_attempts": sum(1 for e in evs if e.get("login_pass_hash")),
        "distinct_passwords": len({e["login_pass_hash"] for e in evs if e.get("login_pass_hash")}),
        "common_passwords": sum(1 for e in evs if e.get("login_pass_common")),
        "uploads": [{"name": e["upload_name"], "size": e["upload_size"], "sha256": e["upload_sha256"],
                     "type": e.get("upload_type", "")} for e in evs if e.get("upload_sha256")],
        "tokens_issued": issued,
        "tokens_replayed": replayed,
        "linked_from": [],
        "_events": evs,
    }


def public_event(e: Dict[str, Any]) -> Dict[str, Any]:
    """An event as the timeline shows it (no hashes)."""
    t = dt.datetime.fromtimestamp(_ts(e), dt.timezone.utc)
    technique = STAGE_ATTACK.get(e.get("stage", ""), ("", ""))
    return {
        "time": t.isoformat(),
        "request_id": e.get("request_id", ""),
        "client_ip": e.get("client_ip", ""),
        "edge_node": e.get("edge_node", ""),
        "method": e.get("method", ""),
        "path": e.get("path", ""),
        "query": e.get("query", ""),
        "stage": e.get("stage", ""),
        "attack_id": technique[0],
        "attack_name": technique[1],
        "category": e.get("category", ""),
        "template": e.get("template", ""),
        "tool": e.get("tool", ""),
        "delay_ms": e.get("delay_ms", 0),
        "body_sample": e.get("body_sample", ""),
        "login": ({"user": e.get("login_user", ""), "password_length": e.get("login_pass_len", 0),
                   "common_password": bool(e.get("login_pass_common"))}
                  if e.get("login_pass_hash") else None),
        "upload": ({"name": e.get("upload_name", ""), "size": e.get("upload_size", 0),
                    "type": e.get("upload_type", ""), "sha256": e.get("upload_sha256", "")}
                   if e.get("upload_sha256") else None),
        "tokens_issued": list(e.get("tokens_issued") or []),
        "token_replayed": e.get("token_replayed", ""),
    }


def public_session(s: Dict[str, Any], with_events: bool = False) -> Dict[str, Any]:
    out = {k: v for k, v in s.items() if not k.startswith("_")}
    out["first_seen"] = dt.datetime.fromtimestamp(s["first_seen"], dt.timezone.utc).isoformat()
    out["last_seen"] = dt.datetime.fromtimestamp(s["last_seen"], dt.timezone.utc).isoformat()
    if with_events:
        out["timeline"] = [public_event(e) for e in s["_events"]]
    return out


def summarize_window(sessions: List[Dict[str, Any]], days: int, now: Optional[float] = None) -> Dict[str, Any]:
    """Counts for the summary cards: sessions per day, furthest stage, tools."""
    now = now if now is not None else time.time()
    tz = dt.timezone(dt.timedelta(hours=7))  # Bangkok, as every chart on the dashboard
    today = dt.datetime.fromtimestamp(now, tz).date()
    per_day = {(today - dt.timedelta(days=i)).isoformat(): 0 for i in range(days - 1, -1, -1)}
    stages = {s: 0 for s in STAGES}
    tools: Dict[str, int] = {}
    ips = set()
    events = 0
    for s in sessions:
        day = dt.datetime.fromtimestamp(s["first_seen"], tz).date().isoformat()
        if day in per_day:
            per_day[day] += 1
        stages[s["max_stage"]] += 1
        tools[s["tool"]] = tools.get(s["tool"], 0) + 1
        ips.update(s["ips"])
        events += s["events"]
    # "Reached" = got at least this far; the funnel the page draws.
    reached = {st: sum(n for k, n in stages.items() if STAGE_RANK[k] >= STAGE_RANK[st]) for st in STAGES}
    return {
        "days": days,
        "sessions": len(sessions),
        "events": events,
        "unique_ips": len(ips),
        "per_day": [{"day": d, "sessions": n} for d, n in per_day.items()],
        "max_stage": stages,
        "reached": reached,
        "tools": sorted(({"tool": t, "sessions": n} for t, n in tools.items()), key=lambda x: -x["sessions"])[:8],
    }


# ------------------------------------------------------------------ alerts

_NOTIFY_GAP_HOURS = 1

STAGE_TH = {
    "recon": "สำรวจ", "loot": "ได้ข้อมูลลับปลอม", "exploit": "พยายามเจาะ",
    "credential_use": "เอา credential ปลอมไปใช้", "persistence": "พยายามฝังไฟล์",
}


def claim_alert(origin_id: str, actor: str, stage: str, now: Optional[dt.datetime] = None) -> bool:
    """True once per (origin, actor, stage, hour): the caller may send."""
    from db import pool
    now = now or dt.datetime.now(dt.timezone.utc)
    hour = now.replace(minute=0, second=0, microsecond=0)
    row = pool.q1(
        "INSERT INTO honeypot_notified (origin_id, actor_id, stage, hour) VALUES (%s::uuid, %s, %s, %s) "
        "ON CONFLICT DO NOTHING RETURNING stage", (origin_id, actor, stage, hour))
    return bool(row)


def format_alert(event: Dict[str, Any], label: str) -> str:
    import html
    e = lambda v: html.escape(str(v), quote=False)  # noqa: E731
    lines = [f"🍯 <b>Honeypot · {e(label or event.get('host', ''))}</b>",
             f"ขั้น: <b>{e(STAGE_TH.get(event['stage'], event['stage']))}</b>"]
    if event.get("token_replayed"):
        lines.append(f"มีคนใช้ honeytoken ({e(event['token_replayed'])}) ที่เราแจกในกับดัก")
    if event.get("upload_sha256"):
        lines.append(f"อัปโหลดไฟล์ {e(event.get('upload_name', ''))} ({event.get('upload_size', 0):,} bytes)")
        lines.append(f"SHA-256 <code>{e(event['upload_sha256'][:16])}…</code>")
    lines.append(f"IP <code>{e(event.get('client_ip', ''))}</code> · {e(event.get('tool', ''))}")
    lines.append(f"{e(event.get('method', ''))} <code>{e(event.get('path', '')[:120])}</code>")
    return "\n".join(lines)


async def notify(event: Dict[str, Any]) -> bool:
    """Push credential use / file drops to the site's team, once per actor,
    stage and hour. Everything else waits for the daily digest."""
    import asyncio
    if event.get("stage") not in ALERT_STAGES or not event.get("origin_id"):
        return False
    try:
        if not await asyncio.to_thread(claim_alert, event["origin_id"], event["actor_id"], event["stage"]):
            return False
        from services import notification_prefs
        from services import telegram_listener as tl
        origin = await asyncio.to_thread(tl.db.get_origin_by_id, event["origin_id"]) or {}
        users = await asyncio.to_thread(tl.recipients_for, event["origin_id"], origin)
        users = await asyncio.to_thread(notification_prefs.filter_users, users, origin, "attacks")
        chats = [u.get("telegram_chat_id") for u in users if u.get("telegram_chat_id")]
        if not chats:
            return False
        from services.site_alerts import _base_url
        base = _base_url()
        link = f"{base}/origins/{event['origin_id']}?tab=honeypot" if base else None
        sent = await tl.send_telegram(chats, format_alert(event, origin.get("label", "")),
                                      [("ดู Honeypot", link)] if link else None)
        logger.info("honeypot alert %s/%s: %d recipient(s)", event["origin_id"], event["stage"], sent)
        return sent > 0
    except Exception as exc:  # noqa: BLE001 - alerting must never break logging
        logger.warning("honeypot alert failed: %s", exc)
        return False


def day_counts(origin_id: str, start: dt.datetime, end: dt.datetime) -> Dict[str, Any]:
    """Sessions and how far they got, one site, one window (daily digest, incident report)."""
    try:
        events = fetch_events(origin_id, start.astimezone(dt.timezone.utc).replace(tzinfo=None),
                              end.astimezone(dt.timezone.utc).replace(tzinfo=None))
    except Exception as exc:  # noqa: BLE001
        logger.warning("honeypot digest counts failed: %s", exc)
        return {"sessions": 0, "ips": 0, "loot": 0, "exploit": 0, "credential_use": 0, "persistence": 0}
    sessions = sessionize(events)
    out = {"sessions": len(sessions), "ips": len({ip for s in sessions for ip in s["ips"]})}
    for st in ("loot", "exploit", "credential_use", "persistence"):
        out[st] = sum(1 for s in sessions if STAGE_RANK[s["max_stage"]] >= STAGE_RANK[st])
    return out
