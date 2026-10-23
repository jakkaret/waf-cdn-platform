"""Telegram alerts someone has to act on, sent as they happen (attack bursts
are grouped separately, services/alert_incidents.py):

- outage:   visitors cannot reach a site. Passive, from what the edge already
            logs: in the last OUTAGE_WINDOW_SECONDS the edge answered
            502/503/504 to at least OUTAGE_MIN_ERRORS requests and to at least
            OUTAGE_ERROR_RATIO of them; or the site's agent tunnel is offline
            (two checks in a row) after it served traffic in the last day.
            Recovered when the edge answers normally again, the tunnel is
            back, or no 5xx was seen for OUTAGE_QUIET_SECONDS.
            Sent to the owner and editors.
- cert:     a site's HTTPS certificate is close to expiry (ssl_cert_monitor),
            to the domain's owner and editors; a domain of no site goes to
            Support.
- team:     someone other than the owner changed the site (domains, settings,
            members, ML rules), from audit_logs, to the owner only.

State is in waf.site_outages / waf.audit_notified (migration 0013): every
transition is claimed with a conditional write and only the claimer sends.
"""
import asyncio
import datetime as dt
import html
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from db import pool

logger = logging.getLogger(__name__)

OUTAGE_WINDOW_SECONDS = 300
OUTAGE_MIN_ERRORS = 5
OUTAGE_ERROR_RATIO = 0.5
RECOVERED_ERROR_RATIO = 0.2
OUTAGE_QUIET_SECONDS = 1800
TUNNEL_OFFLINE_CONFIRM_SECONDS = 110  # two ticks
FIX_ROLES = ("owner", "editor")
TEAM_ACTIONS = {
    "domain.create", "domain.delete", "domain.release", "origin.update",
    "viewer.grant", "editor.grant", "viewer.invite", "editor.invite",
    "viewer.revoke", "editor.revoke", "invite.cancel", "rule.approve", "rule.reject",
}
TEAM_LOOKBACK_SECONDS = 600

_tunnel_offline_since: Dict[str, float] = {}


def _e(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _hm(t: dt.datetime) -> str:
    from services.alert_incidents import BKK
    return t.astimezone(BKK).strftime("%H:%M")


def _base_url() -> Optional[str]:
    try:
        from services.invite_service import public_app_url
        return public_app_url()
    except Exception:
        return None


def _site_button(origin_id: str) -> Optional[list]:
    base = _base_url()
    return [("เปิดหน้าเว็บนี้", f"{base}/origins/{origin_id}")] if base else None


# ---- outages ----------------------------------------------------------------

def host_origins() -> Dict[str, str]:
    """Verified hostname -> origin id, for hosts that belong to exactly one site."""
    owners: Dict[str, set] = {}
    for r in pool.q("SELECT lower(rtrim(hostname, '.')) AS host, origin_id::text AS origin_id FROM origin_hostnames "
                    "WHERE dns_verified AND origin_status NOT IN ('archived', 'deleted')"):
        owners.setdefault(r["host"], set()).add(r["origin_id"])
    return {h: next(iter(ids)) for h, ids in owners.items() if len(ids) == 1}


def edge_counts(ch, now: dt.datetime) -> Tuple[Dict[str, Dict[str, int]], Dict[str, int]]:
    """Per origin: 5xx and total responses in the outage window, and non-5xx
    responses in the last day (did the site serve anyone lately)."""
    naive = now.astimezone(dt.timezone.utc).replace(tzinfo=None)
    window = ch.client.query(
        "SELECT host, countIf(status_code IN (502, 503, 504)) AS e, count() AS t FROM access_logs "
        "WHERE timestamp > {since:DateTime} AND timestamp <= {now:DateTime} AND host != '' GROUP BY host",
        parameters={"since": naive - dt.timedelta(seconds=OUTAGE_WINDOW_SECONDS), "now": naive}).result_rows
    day = ch.client.query(
        "SELECT host, countIf(status_code < 500) AS ok FROM access_logs "
        "WHERE timestamp > {since:DateTime} AND host != '' GROUP BY host",
        parameters={"since": naive - dt.timedelta(days=1)}).result_rows
    hosts = host_origins()
    per: Dict[str, Dict[str, int]] = {}
    for host, e, t in window:
        oid = hosts.get(host)
        if oid:
            c = per.setdefault(oid, {"errors": 0, "total": 0})
            c["errors"] += int(e)
            c["total"] += int(t)
    served: Dict[str, int] = {}
    for host, ok in day:
        oid = hosts.get(host)
        if oid:
            served[oid] = served.get(oid, 0) + int(ok)
    return per, served


def tunnel_states(online_names: Optional[set]) -> Dict[str, bool]:
    """Active tunnel sites -> online now. Empty when the FRP poll failed."""
    if online_names is None:
        return {}
    from api.origins import _tunnel_is_online
    rows = pool.q("SELECT id::text AS origin_id, tunnel_name FROM origins WHERE is_tunnel AND tunnel_name <> '' "
                  "AND archived_at IS NULL AND deleted_at IS NULL")
    return {r["origin_id"]: _tunnel_is_online(r["tunnel_name"], online_names) for r in rows}


def advance_outages(now: dt.datetime, per: Dict[str, Dict[str, int]], served: Dict[str, int],
                    tunnels: Dict[str, bool], mono: Optional[float] = None) -> List[Tuple[str, Dict[str, Any]]]:
    mono = time.monotonic() if mono is None else mono
    events = []
    for o in pool.q("SELECT * FROM site_outages WHERE ended_at IS NULL"):
        oid = str(o["origin_id"])
        c = per.get(oid, {"errors": 0, "total": 0})
        bad = c["errors"] >= OUTAGE_MIN_ERRORS and c["errors"] >= OUTAGE_ERROR_RATIO * c["total"]
        if o["reason"] == "tunnel_offline":
            recovered, how = tunnels.get(oid, True), "back"
        elif bad:
            recovered, how = False, ""
        elif c["total"] and c["errors"] < RECOVERED_ERROR_RATIO * c["total"]:
            recovered, how = True, "back"
        else:
            recovered = (now - o["last_bad_at"]).total_seconds() >= OUTAGE_QUIET_SECONDS
            how = "quiet"
        if recovered:
            row = pool.q1("UPDATE site_outages SET ended_at = %s WHERE outage_id = %s AND ended_at IS NULL RETURNING *",
                          (now, o["outage_id"]))
            if row:
                events.append(("up", {**row, "how": how}))
        elif o["reason"] == "upstream_errors" and bad:
            pool.exec_("UPDATE site_outages SET last_bad_at = %s, error_count = error_count + %s, "
                       "request_count = request_count + %s WHERE outage_id = %s",
                       (now, c["errors"], c["total"], o["outage_id"]))

    for oid, c in per.items():
        if c["errors"] >= OUTAGE_MIN_ERRORS and c["errors"] >= OUTAGE_ERROR_RATIO * c["total"]:
            row = _open(oid, "upstream_errors", now, c)
            if row:
                events.append(("down", row))
    for oid, online in tunnels.items():
        if online:
            _tunnel_offline_since.pop(oid, None)
            continue
        first = _tunnel_offline_since.setdefault(oid, mono)
        if mono - first >= TUNNEL_OFFLINE_CONFIRM_SECONDS and served.get(oid, 0) > 0:
            row = _open(oid, "tunnel_offline", now, {"errors": 0, "total": 0})
            if row:
                events.append(("down", row))
    return events


def _open(origin_id: str, reason: str, now: dt.datetime, c: Dict[str, int]) -> Optional[Dict[str, Any]]:
    return pool.q1(
        "INSERT INTO site_outages (origin_id, reason, started_at, last_bad_at, error_count, request_count) "
        "VALUES (%s::uuid, %s, %s, %s, %s, %s) ON CONFLICT (origin_id) WHERE ended_at IS NULL DO NOTHING RETURNING *",
        (origin_id, reason, now, now, c["errors"], c["total"]))


def format_down(o: Dict[str, Any], label: str) -> str:
    if o["reason"] == "tunnel_offline":
        return (f"⚠️ <b>{_e(label)}: agent หลุดการเชื่อมต่อ</b>\n"
                f"tunnel ของ agent ออฟไลน์ตั้งแต่ {_hm(o['started_at'])} น. ผู้เข้าเว็บจะเปิดเว็บไม่ได้\n"
                "เช็คว่า agent บนเซิร์ฟเวอร์ยังทำงานอยู่")
    return (f"⚠️ <b>{_e(label)}: ผู้เข้าเว็บเปิดเว็บไม่ได้</b>\n"
            f"ใน 5 นาทีล่าสุด เซิร์ฟเวอร์ต้นทางตอบ error 502/503/504 "
            f"{o['error_count']:,} จาก {o['request_count']:,} คำขอ (เริ่ม {_hm(o['started_at'])} น.)\n"
            "เช็คว่าเซิร์ฟเวอร์ต้นทางเปิดอยู่ และ firewall ให้ edge ของ WAF เข้าได้")


def format_up(o: Dict[str, Any], label: str) -> str:
    minutes = max(1, -(-int((o["ended_at"] - o["started_at"]).total_seconds()) // 60))
    if o.get("how") == "quiet":
        return (f"✅ <b>{_e(label)}: ไม่พบ error แล้ว</b>\n"
                f"ไม่มี error 502/503/504 ใน 30 นาทีที่ผ่านมา (เริ่มมีปัญหา {_hm(o['started_at'])} น.)")
    what = "agent เชื่อมต่อกลับมาแล้ว" if o["reason"] == "tunnel_offline" else "เว็บตอบปกติแล้ว"
    return (f"✅ <b>{_e(label)} กลับมาใช้งานได้</b>\n"
            f"{what} · ล่มไปราว {minutes} นาที ({_hm(o['started_at'])}–{_hm(o['ended_at'])} น.)")


async def outage_tick(now: Optional[dt.datetime] = None, ch=None) -> List[Tuple[str, Dict[str, Any]]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    if ch is None:
        from services.clickhouse_service import ClickHouseService
        ch = ClickHouseService()
    if not getattr(ch, "connected", False):
        return []
    try:
        from services.origin_service import get_live_proxies, frp_admin_auth
        online = None
        if frp_admin_auth() is not None:
            proxies = await get_live_proxies(force=True)
            online = {p.get("name") for p in proxies if p.get("status") == "online" and p.get("name")} if proxies else None
    except Exception:
        online = None
    per, served = await asyncio.to_thread(edge_counts, ch, now)
    tunnels = await asyncio.to_thread(tunnel_states, online)
    events = await asyncio.to_thread(advance_outages, now, per, served, tunnels)
    for kind, o in events:
        try:
            await _notify_outage(kind, o)
        except Exception:
            logger.exception("outage %s notification failed", kind)
    return events


async def _notify_outage(kind: str, o: Dict[str, Any]) -> None:
    from services import telegram_listener as tl
    oid = str(o["origin_id"])
    origin = await asyncio.to_thread(tl.db.get_origin_by_id, oid) or {}
    label = origin.get("label") or "เว็บของคุณ"
    text = format_down(o, label) if kind == "down" else format_up(o, label)
    chats = [u.get("telegram_chat_id") for u in await asyncio.to_thread(tl.recipients_for, oid, origin, FIX_ROLES)]
    sent = await tl.send_telegram(chats, text, _site_button(oid))
    col = "down_notified_at" if kind == "down" else "up_notified_at"
    await asyncio.to_thread(pool.exec_, f"UPDATE site_outages SET {col} = now() WHERE outage_id = %s", (o["outage_id"],))
    logger.info("outage %s %s: %d of %d recipient(s)", o["outage_id"], kind, sent, len(chats))


# ---- certificates -----------------------------------------------------------

def origin_for_host(host: str) -> Optional[str]:
    return host_origins().get(str(host or "").strip().lower().rstrip("."))


def format_cert(domain: str, days_remaining: int, not_after: str) -> str:
    when = "หมดอายุแล้ว" if days_remaining < 0 else f"จะหมดอายุใน {days_remaining} วัน"
    return (f"🔒 <b>ใบรับรอง HTTPS ของ {_e(domain)} {when}</b>\n"
            f"หมดอายุ {_e(str(not_after)[:10])} · ปกติระบบต่ออายุให้เองก่อนถึงตอนนี้ แปลว่าการต่ออายุยังไม่สำเร็จ\n"
            "เช็คว่า DNS ของโดเมนยังชี้มาที่ WAF")


async def notify_cert(domain: str, days_remaining: int, not_after: str) -> int:
    """ssl_cert_monitor's send_alert: the domain's owner and editors, or
    Support when the domain belongs to no site (a platform hostname)."""
    from services import telegram_listener as tl
    oid = await asyncio.to_thread(origin_for_host, domain)
    origin = (await asyncio.to_thread(tl.db.get_origin_by_id, oid) or {}) if oid else {}
    scope = oid or tl.db.ALERTS_UNATTRIBUTED
    chats = [u.get("telegram_chat_id") for u in await asyncio.to_thread(tl.recipients_for, scope, origin, FIX_ROLES)]
    return await tl.send_telegram(chats, format_cert(domain, days_remaining, not_after),
                                  _site_button(oid) if oid else None)


# ---- team changes -----------------------------------------------------------

def claim_team_events(now: dt.datetime) -> List[Dict[str, Any]]:
    """Recent site-scoped audit events not yet told, claimed one by one. Only
    TEAM_LOOKBACK_SECONDS back, so the first start does not replay history."""
    rows = pool.q(
        "SELECT a.* FROM audit_logs a WHERE a.scope_id <> 'global' AND a.action = ANY(%s) "
        "AND a.occurred_at > %s - make_interval(secs => %s) "
        "AND NOT EXISTS (SELECT 1 FROM audit_notified n WHERE n.event_id = a.event_id) ORDER BY a.event_id",
        (sorted(TEAM_ACTIONS), now, TEAM_LOOKBACK_SECONDS))
    claimed = []
    for r in rows:
        if pool.q1("INSERT INTO audit_notified (event_id) VALUES (%s) ON CONFLICT DO NOTHING RETURNING event_id",
                   (r["event_id"],)):
            claimed.append(r)
    return claimed


def format_team(ev: Dict[str, Any], label: str, actor_is_support: bool) -> str:
    who = f"{ev.get('actor_username') or 'ไม่ทราบชื่อ'}{' (Support)' if actor_is_support else ''}"
    return (f"👥 <b>{_e(label)}</b>: มีการเปลี่ยนแปลงโดย {_e(who)}\n"
            f"{_e(ev['summary'])}\n"
            f"{_hm(ev['occurred_at'])} น.")


async def team_tick(now: Optional[dt.datetime] = None) -> int:
    from services import telegram_listener as tl
    now = now or dt.datetime.now(dt.timezone.utc)
    sent = 0
    for ev in await asyncio.to_thread(claim_team_events, now):
        origin = await asyncio.to_thread(tl.db.get_origin_by_id, ev["scope_id"]) or {}
        owner = origin.get("admin_user_id")
        actor = str(ev.get("actor_user_id") or "")
        if not owner or actor == str(owner):
            continue  # nobody to tell, or the owner did it themselves
        users = await asyncio.to_thread(tl._get_telegram_users)
        chats = [u.get("telegram_chat_id") for u in tl._alert_recipients(users, origin, False, ("owner",))]
        actor_is_support = await asyncio.to_thread(_is_support, actor)
        sent += await tl.send_telegram(chats, format_team(ev, origin.get("label") or "เว็บของคุณ", actor_is_support),
                                       _site_button(ev["scope_id"]))
    return sent


def _is_support(user_id: str) -> bool:
    if not user_id:
        return False
    try:
        row = pool.q1("SELECT role FROM users WHERE user_id = %s::uuid", (user_id,))
    except Exception:
        return False
    return bool(row and row["role"] == "admin")


async def tick(now: Optional[dt.datetime] = None) -> None:
    for name, step in (("outage", outage_tick), ("team", team_tick)):
        try:
            await step(now)
        except Exception:
            logger.exception("site alert %s tick failed", name)
