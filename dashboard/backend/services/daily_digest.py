"""Daily summary per site, for people who turned it on (notification_prefs
"digest", off by default). Sent once per person, site and Bangkok day, from
DIGEST_HOUR Bangkok time on, about the day before; waf.digest_sent
(migration 0014) is claimed before each send so it never repeats."""
import asyncio
import datetime as dt
import html
import logging
from typing import Any, Dict, List, Optional

from db import pool
from services import notification_prefs
from services.alert_incidents import ATTACK_TYPE_TH, BKK

logger = logging.getLogger(__name__)

DIGEST_HOUR = 8


def _e(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _day_bounds(day: dt.date):
    start = dt.datetime.combine(day, dt.time(0), tzinfo=BKK)
    return start, start + dt.timedelta(days=1)


def due(day: dt.date) -> List[Dict[str, Any]]:
    """(user, site) pairs that want a digest for `day` and have not had it."""
    return pool.q(
        "SELECT p.user_id::text AS user_id, p.origin_id::text AS origin_id, u.telegram_chat_id "
        "FROM notification_prefs p JOIN users u ON u.user_id = p.user_id "
        "JOIN origins o ON o.id = p.origin_id AND o.archived_at IS NULL AND o.deleted_at IS NULL "
        "WHERE p.digest AND u.telegram_chat_id IS NOT NULL AND NOT EXISTS ("
        "  SELECT 1 FROM digest_sent d WHERE d.user_id = p.user_id AND d.origin_id = p.origin_id AND d.day = %s)",
        (day,))


def day_stats(origin_id: str, day: dt.date) -> Dict[str, Any]:
    start, end = _day_bounds(day)
    prev_start = start - dt.timedelta(days=1)
    head = pool.q1("SELECT count(*)::int AS n, count(DISTINCT ip)::int AS ips FROM alerts "
                   "WHERE origin_id = %s::uuid AND created_at >= %s AND created_at < %s", (origin_id, start, end))
    prev = pool.q1("SELECT count(*)::int AS n FROM alerts WHERE origin_id = %s::uuid AND created_at >= %s "
                   "AND created_at < %s", (origin_id, prev_start, start))
    types = pool.q("SELECT attack_type AS t, count(*)::int AS n FROM alerts WHERE origin_id = %s::uuid "
                   "AND created_at >= %s AND created_at < %s AND attack_type IS NOT NULL "
                   "GROUP BY 1 ORDER BY 2 DESC LIMIT 2", (origin_id, start, end))
    incidents = pool.q1("SELECT count(*)::int AS n FROM alert_incidents WHERE scope = %s "
                        "AND opened_at >= %s AND opened_at < %s", (origin_id, start, end))
    outages = pool.q1("SELECT count(*)::int AS n FROM site_outages WHERE origin_id = %s::uuid "
                      "AND started_at >= %s AND started_at < %s", (origin_id, start, end))
    from services import honeypot
    return {"blocked": head["n"], "ips": head["ips"], "prev_blocked": prev["n"],
            "types": [(r["t"], r["n"]) for r in types], "incidents": incidents["n"], "outages": outages["n"],
            "honeypot": honeypot.day_counts(origin_id, start, end)}


def format_digest(label: str, day: dt.date, s: Dict[str, Any]) -> str:
    lines = [f"📊 <b>สรุปเมื่อวาน · {_e(label)}</b> ({day.day}/{day.month})"]
    if not s["blocked"]:
        lines.append(f"ไม่มีการบล็อก (วันก่อนหน้า {s['prev_blocked']:,})")
    else:
        lines.append(f"บล็อก <b>{s['blocked']:,}</b> ครั้ง (วันก่อนหน้า {s['prev_blocked']:,}) · {s['ips']:,} IP")
        total = s["blocked"]
        kinds = ", ".join(f"{_e(ATTACK_TYPE_TH.get(t, t))} {round(100 * n / total)}%" for t, n in s["types"])
        if kinds:
            lines.append(f"ประเภทหลัก: {kinds}")
    lines.append(f"เหตุการณ์โจมตี {s['incidents']} ครั้ง · เว็บเปิดไม่ได้ {s['outages']} ครั้ง")
    hp = s.get("honeypot") or {}
    if hp.get("sessions"):
        deeper = [f"ได้ข้อมูลลับปลอม {hp['loot']}" if hp.get("loot") else "",
                  f"พยายามเจาะ {hp['exploit']}" if hp.get("exploit") else "",
                  f"ใช้ credential ปลอม {hp['credential_use']}" if hp.get("credential_use") else "",
                  f"พยายามฝังไฟล์ {hp['persistence']}" if hp.get("persistence") else ""]
        detail = " · ".join(d for d in deeper if d)
        lines.append(f"🍯 Honeypot {hp['sessions']:,} session จาก {hp['ips']:,} IP" + (f" ({detail})" if detail else ""))
    return "\n".join(lines)


async def tick(now: Optional[dt.datetime] = None) -> int:
    from services import telegram_listener as tl
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(BKK)
    if now.hour < DIGEST_HOUR:
        return 0
    day = now.date() - dt.timedelta(days=1)
    sent = 0
    for pair in await asyncio.to_thread(due, day):
        origin = await asyncio.to_thread(tl.db.get_origin_by_id, pair["origin_id"]) or {}
        if not notification_prefs.role_on(origin, pair["user_id"]):
            continue  # no longer on the site's team
        claimed = await asyncio.to_thread(
            pool.q1, "INSERT INTO digest_sent (user_id, origin_id, day) VALUES (%s, %s, %s) "
                     "ON CONFLICT DO NOTHING RETURNING day", (pair["user_id"], pair["origin_id"], day))
        if not claimed:
            continue
        stats = await asyncio.to_thread(day_stats, pair["origin_id"], day)
        from services.site_alerts import _base_url
        base = _base_url()
        sent += await tl.send_telegram([pair["telegram_chat_id"]],
                                       format_digest(origin.get("label") or "เว็บของคุณ", day, stats),
                                       [("เปิด Alert Center", f"{base}/alerts")] if base else None)
    return sent
