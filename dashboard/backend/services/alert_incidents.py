"""Attack incidents: blocked requests grouped per site into one event.

A blocked request is the WAF doing its job, so it is stored (alerts table)
but not pushed. Attacks arrive in bursts -- on Main, 21-23 Oct 2026, 83% of
891 blocks fell in three 5-minute bursts from a single IP each -- so one
burst becomes one incident and costs the reader two messages, not dozens:

- open:     in the last WINDOW_SECONDS a site was blocked OPEN_TOTAL times,
            or one IP was blocked OPEN_PER_IP times (the site's sensitivity,
            services/notification_prefs.py; these are "medium") -> push
            "under attack".
- ongoing:  counts refresh every tick, nothing is pushed; once, if the
            incident grows to ESCALATE_FACTOR x its opening count, push an update.
- close:    no block for QUIET_CLOSE_SECONDS -> push a summary (Gemini writes
            two lines once per incident; without it the numbers go alone).

State lives in waf.alert_incidents (migration 0012), so a restart neither
loses nor repeats a message. Every transition is claimed with a conditional
write and only the claimer sends. Recipients are the site's team, and
Support only for unattributed traffic or a site under a support grant
(telegram_listener.recipients_for).
"""
import asyncio
import datetime as dt
import html
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from db import pool
from services import notification_prefs

logger = logging.getLogger(__name__)

UNATTRIBUTED = "unattributed"
WINDOW_SECONDS = 300
OPEN_TOTAL, OPEN_PER_IP = notification_prefs.SENSITIVITY["medium"]
QUIET_CLOSE_SECONDS = 1800
ESCALATE_FACTOR = 10
TICK_SECONDS = 60
BKK = ZoneInfo("Asia/Bangkok")

# CRS names readers see in the message. Anything else keeps its own name.
ATTACK_TYPE_TH = {
    "WAF Security Block": "คำขอที่ WAF ห้าม",
    "Restricted File Access Attempt": "พยายามเปิดไฟล์ต้องห้าม",
    "Restricted File Access Attempt: AI Coding Assistant Artifact": "หาไฟล์ตั้งค่าของเครื่องมือ AI",
    "URL file extension is restricted by policy": "ขอไฟล์นามสกุลต้องห้าม",
    "Attempt to access a backup or working file": "หาไฟล์สำรอง",
    "Invalid character in request (null character)": "อักขระแปลกปลอมใน URL",
}


def _scope_clause(scope: str) -> Tuple[str, tuple]:
    if scope == UNATTRIBUTED:
        return "origin_id IS NULL", ()
    return "origin_id = %s::uuid", (scope,)


def _now(now: Optional[dt.datetime]) -> dt.datetime:
    return now or dt.datetime.now(dt.timezone.utc)


def window_counts(now: dt.datetime) -> List[Dict[str, Any]]:
    """Per scope over the last WINDOW_SECONDS: blocks, the busiest IP's
    blocks, and the first block's time."""
    return pool.q(
        "SELECT scope, max(origin_id) AS origin_id, sum(n)::int AS n, max(n)::int AS top_ip, min(first_at) AS first_at "
        "FROM (SELECT coalesce(origin_id::text, %s) AS scope, origin_id::text AS origin_id, ip, "
        "             count(*) AS n, min(created_at) AS first_at "
        "      FROM alerts WHERE created_at > %s - make_interval(secs => %s) AND created_at <= %s "
        "      GROUP BY 1, 2, 3) per_ip GROUP BY scope",
        (UNATTRIBUTED, now, WINDOW_SECONDS, now))


def incident_stats(scope: str, since: dt.datetime, until: dt.datetime) -> Dict[str, Any]:
    clause, args = _scope_clause(scope)
    where = f"{clause} AND created_at >= %s AND created_at <= %s"
    params = args + (since, until)
    head = pool.q1(f"SELECT count(*)::int AS n, count(DISTINCT ip)::int AS ips, max(created_at) AS last_at "
                   f"FROM alerts WHERE {where}", params)

    def top(col: str, limit: int) -> List[List[Any]]:
        rows = pool.q(f"SELECT {col} AS k, count(*)::int AS n FROM alerts WHERE {where} "
                      f"GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT {limit}", params)
        return [[r["k"], r["n"]] for r in rows if r["k"] is not None]

    return {
        "blocked_count": head["n"], "ip_count": head["ips"], "last_at": head["last_at"],
        "top_ips": top("ip", 3), "top_types": top("attack_type", 3),
        "top_paths": [[str(p)[:80], n] for p, n in top("url", 5)],
        "top_domains": top("nullif(domain, '')", 1),
    }


def _row(r: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(r)
    out["incident_id"] = str(r["incident_id"])
    out["origin_id"] = str(r["origin_id"]) if r.get("origin_id") else None
    return out


def _open_new(now: dt.datetime) -> List[Dict[str, Any]]:
    opened = []
    windows = window_counts(now)
    levels = notification_prefs.sensitivities([w["origin_id"] for w in windows])
    for w in windows:
        total, per_ip = notification_prefs.thresholds(levels.get(w["origin_id"] or ""))
        if w["n"] < total and w["top_ip"] < per_ip:
            continue
        s = incident_stats(w["scope"], w["first_at"], now)
        row = pool.q1(
            "INSERT INTO alert_incidents (scope, origin_id, opened_at, last_seen_at, open_count, blocked_count, "
            "ip_count, top_ips, top_types, top_paths) "
            "VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb) "
            "ON CONFLICT (scope) WHERE closed_at IS NULL DO NOTHING RETURNING *",
            (w["scope"], w["origin_id"], w["first_at"], s["last_at"] or now, w["n"], s["blocked_count"],
             s["ip_count"], json.dumps(s["top_ips"]), json.dumps(s["top_types"]), json.dumps(s["top_paths"])))
        if row:
            opened.append({**_row(row), "domain": (s["top_domains"] or [[None]])[0][0]})
    return opened


def _advance_open(now: dt.datetime) -> List[Tuple[str, Dict[str, Any]]]:
    events = []
    for inc in pool.q("SELECT * FROM alert_incidents WHERE closed_at IS NULL"):
        s = incident_stats(inc["scope"], inc["opened_at"], now)
        last = s["last_at"] or inc["last_seen_at"]
        pool.exec_(
            "UPDATE alert_incidents SET last_seen_at = %s, blocked_count = %s, ip_count = %s, top_ips = %s::jsonb, "
            "top_types = %s::jsonb, top_paths = %s::jsonb WHERE incident_id = %s AND closed_at IS NULL",
            (last, s["blocked_count"], s["ip_count"], json.dumps(s["top_ips"]), json.dumps(s["top_types"]),
             json.dumps(s["top_paths"]), inc["incident_id"]))
        domain = (s["top_domains"] or [[None]])[0][0]
        if (now - last).total_seconds() >= QUIET_CLOSE_SECONDS:
            row = pool.q1("UPDATE alert_incidents SET closed_at = %s WHERE incident_id = %s AND closed_at IS NULL "
                          "RETURNING *", (now, inc["incident_id"]))
            if row:
                events.append(("close", {**_row(row), "domain": domain}))
        elif s["blocked_count"] >= ESCALATE_FACTOR * inc["open_count"] and inc["escalated_notified_at"] is None:
            row = pool.q1("UPDATE alert_incidents SET escalated_notified_at = %s WHERE incident_id = %s "
                          "AND escalated_notified_at IS NULL RETURNING *", (now, inc["incident_id"]))
            if row:
                events.append(("escalate", {**_row(row), "domain": domain}))
    return events


def advance(now: Optional[dt.datetime] = None) -> List[Tuple[str, Dict[str, Any]]]:
    """One pass: close or escalate what is open, then open what is new. Only
    the last WINDOW_SECONDS is ever looked at for opening, so a first start
    never reports old bursts."""
    now = _now(now)
    events = _advance_open(now)
    events += [("open", inc) for inc in _open_new(now)]
    return events


# ---- messages ---------------------------------------------------------------

def _e(value: Any) -> str:
    return html.escape(str(value), quote=False)


def report_html(text: str) -> str:
    """The AI's report text (REPORT_STYLE: "- " items, **bold**, `code`) as
    Telegram HTML. Escaped first, so only these three marks become tags."""
    lines = []
    for line in _e(text).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- "):
            line = "• " + line[2:]
        line = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", line)
        line = re.sub(r"`([^`]+)`", r"<code>\1</code>", line)
        lines.append(line)
    return "\n".join(lines)


def _hm(t: dt.datetime, ref: Optional[dt.datetime] = None) -> str:
    local = t.astimezone(BKK)
    if ref is not None and ref.astimezone(BKK).date() != local.date():
        return local.strftime("%d/%m %H:%M")
    return local.strftime("%H:%M")


def _types(inc: Dict[str, Any]) -> str:
    names = [ATTACK_TYPE_TH.get(t, t) for t, _n in (inc.get("top_types") or [])[:2]]
    return ", ".join(dict.fromkeys(names)) or "ไม่ระบุ"


def _site(inc: Dict[str, Any], label: Optional[str]) -> str:
    if inc["scope"] == UNATTRIBUTED:
        return "traffic ที่ไม่ตรงกับเว็บไหน"
    return label or inc.get("domain") or "เว็บของคุณ"


def _top_ip_line(inc: Dict[str, Any]) -> str:
    ips = inc.get("top_ips") or []
    if not ips:
        return ""
    ip, n = ips[0]
    return f"IP หลัก: <code>{_e(ip)}</code> ({n:,} ครั้ง)\n"


def _domain_line(inc: Dict[str, Any], label: Optional[str]) -> str:
    d = inc.get("domain")
    return f"โดเมน: {_e(d)}\n" if d and label and d != label and inc["scope"] != UNATTRIBUTED else ""


def _minutes(inc: Dict[str, Any]) -> int:
    return max(1, -(-int((inc["last_seen_at"] - inc["opened_at"]).total_seconds()) // 60))


def format_open(inc: Dict[str, Any], label: Optional[str]) -> str:
    return (
        f"🔴 <b>{_e(_site(inc, label))} กำลังถูกโจมตี</b>\n"
        f"{_domain_line(inc, label)}"
        f"บล็อก <b>{inc['open_count']:,} ครั้ง</b> ใน 5 นาที จาก <b>{inc['ip_count']:,} IP</b>\n"
        f"ประเภทหลัก: {_e(_types(inc))}\n"
        f"{_top_ip_line(inc)}"
        f"เริ่ม {_hm(inc['opened_at'])} น. · คำขอเหล่านี้ถูกบล็อกแล้ว จะสรุปให้อีกครั้งเมื่อเงียบไป 30 นาที"
    )


def format_escalate(inc: Dict[str, Any], label: Optional[str]) -> str:
    return (
        f"🔴 <b>{_e(_site(inc, label))}: การโจมตีหนักขึ้น</b>\n"
        f"ตั้งแต่ {_hm(inc['opened_at'])} น. บล็อกแล้ว <b>{inc['blocked_count']:,} ครั้ง</b> "
        f"จาก <b>{inc['ip_count']:,} IP</b>\n"
        f"ประเภทหลัก: {_e(_types(inc))}\n"
        f"{_top_ip_line(inc)}".rstrip("\n")
    )


def format_close(inc: Dict[str, Any], label: Optional[str], summary: Optional[str]) -> str:
    text = (
        f"✅ <b>{_e(_site(inc, label))}: เหตุการณ์จบแล้ว</b>\n"
        f"{_hm(inc['opened_at'])}–{_hm(inc['last_seen_at'], inc['opened_at'])} น. ({_minutes(inc)} นาที) · "
        f"บล็อก <b>{inc['blocked_count']:,} ครั้ง</b> · {inc['ip_count']:,} IP\n"
        f"ประเภทหลัก: {_e(_types(inc))}\n"
        f"{_top_ip_line(inc)}"
    )
    if summary:
        text += f"\n<b>สรุปโดย AI</b>\n{report_html(summary)}"
    return text.rstrip("\n")


def incident_link(inc: Dict[str, Any]) -> Optional[str]:
    try:
        from services.invite_service import public_app_url
        return f"{public_app_url()}/alerts?incident={inc['incident_id']}"
    except Exception:
        return None


# ---- worker -----------------------------------------------------------------

async def _notify(kind: str, inc: Dict[str, Any]) -> None:
    from services import telegram_listener as tl
    from services.gemini_service import gemini_service

    origin = {}
    if inc["scope"] != UNATTRIBUTED:
        origin = await asyncio.to_thread(tl.db.get_origin_by_id, inc["scope"]) or {}
    label = origin.get("label")

    if kind == "open":
        text = format_open(inc, label)
    elif kind == "escalate":
        text = format_escalate(inc, label)
    else:
        stats = {
            "minutes": _minutes(inc), "blocked": inc["blocked_count"], "distinct_ips": inc["ip_count"],
            "attack_types": inc.get("top_types"), "paths": inc.get("top_paths"),
        }
        summary = await gemini_service.summarize_incident(stats)
        await asyncio.to_thread(
            pool.exec_, "UPDATE alert_incidents SET summary = %s, summary_by_ai = %s WHERE incident_id = %s",
            (summary, bool(summary), inc["incident_id"]))
        text = format_close(inc, label, summary)

    users = await asyncio.to_thread(tl.recipients_for, inc["scope"], origin)
    users = await asyncio.to_thread(notification_prefs.filter_users, users, origin, "attacks")
    chats = [u.get("telegram_chat_id") for u in users]
    link = incident_link(inc)
    sent = await tl.send_telegram(chats, text, [("ดูเหตุการณ์", link)] if link else None)
    column = {"open": "open_notified_at", "escalate": "escalated_notified_at", "close": "close_notified_at"}[kind]
    await asyncio.to_thread(pool.exec_, f"UPDATE alert_incidents SET {column} = now() WHERE incident_id = %s",
                            (inc["incident_id"],))
    logger.info("incident %s %s: %d of %d recipient(s)", inc["incident_id"], kind, sent, len(chats))


async def tick(now: Optional[dt.datetime] = None) -> List[Tuple[str, Dict[str, Any]]]:
    events = await asyncio.to_thread(advance, now)
    for kind, inc in events:
        try:
            await _notify(kind, inc)
        except Exception:
            logger.exception("incident %s notification failed", kind)
    return events


async def incident_worker() -> None:
    print(f"[Alert Incidents] worker active (attack incidents, outages, team changes), tick every {TICK_SECONDS}s")
    while True:
        try:
            await tick()
        except Exception:
            logger.exception("alert incident tick failed")
        from services import site_alerts
        await site_alerts.tick()
        await asyncio.sleep(TICK_SECONDS)
