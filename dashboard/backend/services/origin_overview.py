"""One summary row per origin for the Origins list (GET /api/origins/overview):
requests and blocked requests over the last 24 hours, the state of the five
protections, and how many domains are live.

Scope comes from the same places the per-origin pages use, so the list never
shows more than opening each origin would:
- which origins: origin_service.get_origins_visible_to_user (owned + granted);
- which traffic: each origin's DNS-verified domains and tunnel hosts
  (tenant_service.verified_scope_keywords), matched by exact host. An origin
  with no verified host counts nothing (fail closed).
Every per-origin lookup is best effort: a failing store leaves that field
None ("unknown") instead of failing the whole list.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from services import ml_gate
from services.request_count import requests_sql
from services.captcha_config import get_origin_config as get_captcha_config
from services.otp_config import get_origin_config as get_otp_config
from services.tenant_service import verified_scope_keywords

logger = logging.getLogger(__name__)

BLOCKED_SQL = "status_code IN (403, 429) OR alert = 1"

_CH = None


def clickhouse():
    """One shared client, created on first use (like api/analytics.py's)."""
    global _CH
    if _CH is None:
        from services.clickhouse_service import ClickHouseService
        _CH = ClickHouseService()
    return _CH


def _safe(fn, *args, default=None):
    try:
        return fn(*args)
    except Exception as exc:  # one unreachable store must not hide the list
        logger.warning("origin overview: %s failed: %s", getattr(fn, "__name__", fn), exc)
        return default


def traffic_24h(ch, origins: List[Dict[str, Any]], domain_rows: List[Dict[str, Any]]) -> Dict[str, Optional[Dict[str, int]]]:
    """{origin_id: {"requests", "blocked"}} for the last 24 h, or None per
    origin when the log store is unreachable."""
    hosts_by_origin: Dict[str, set] = {}
    for o in origins:
        oid = str(o.get("id"))
        mine = [d for d in domain_rows if str(d.get("origin_id")) == oid]
        hosts_by_origin[oid] = {h.strip().lower().rstrip(".") for h in verified_scope_keywords([o], mine) if h}
    all_hosts = sorted({h for hs in hosts_by_origin.values() for h in hs})
    empty = {oid: {"requests": 0, "blocked": 0} for oid in hosts_by_origin}
    if not all_hosts:
        return empty
    if not getattr(ch, "connected", False) or not getattr(ch, "client", None):
        return {oid: None for oid in hosts_by_origin}
    try:
        res = ch.client.query(
            f"""
            SELECT host, {requests_sql()} AS total, {requests_sql(BLOCKED_SQL)} AS blocked
            FROM access_logs
            WHERE timestamp >= now() - INTERVAL 24 HOUR AND host IN {{hosts:Array(String)}}
            GROUP BY host
            """,
            parameters={"hosts": all_hosts},
        )
        per_host = {str(r[0]).lower(): (int(r[1]), int(r[2])) for r in res.result_rows}
    except Exception as exc:
        logger.warning("origin overview: traffic query failed: %s", exc)
        return {oid: None for oid in hosts_by_origin}
    out: Dict[str, Optional[Dict[str, int]]] = {}
    for oid, hosts in hosts_by_origin.items():
        req = sum(per_host.get(h, (0, 0))[0] for h in hosts)
        blk = sum(per_host.get(h, (0, 0))[1] for h in hosts)
        out[oid] = {"requests": req, "blocked": blk}
    return out


def protection(origin: Dict[str, Any], tenant_rules, ip_list, rate_list) -> Dict[str, Any]:
    """The five protections as the detail page shows them. Counts are of
    rules in force; None means that store could not be read."""
    oid = str(origin.get("id"))
    rules = _safe(tenant_rules.list, [oid])
    decoys = _safe(tenant_rules.list_decoys, oid, origin.get("tech_stack_tags"))
    ml = _safe(ml_gate.get_settings, oid)
    ips = _safe(ip_list, oid)
    rates = _safe(rate_list, oid)
    captcha = _safe(get_captcha_config, oid)
    otp = _safe(get_otp_config, oid)
    return {
        "waf": {
            # CRS itself is always on for every origin; these are the owner's additions.
            "custom_rules": None if rules is None else sum(1 for r in rules if not r.get("decoy")),
            "decoys": None if decoys is None else sum(1 for d in decoys if d.get("enabled")),
        },
        "ml": None if ml is None else {
            "mode": ml.get("mode"),
            "challenge_score": ml.get("challenge_score"),
            "block_score": ml.get("block_score"),
        },
        "ip": None if ips is None else {
            "block": sum(1 for r in ips if r.get("action") == "block"),
            "allow": sum(1 for r in ips if r.get("action") == "allow"),
        },
        "rate": None if rates is None else {
            "rules": len(rates),
            "enabled": sum(1 for r in rates if r.get("enabled", True)),
        },
        "shield": {
            "captcha": None if captcha is None else bool(captcha.get("enabled")),
            "otp": None if otp is None else bool(otp.get("enabled")),
        },
    }


def domains_summary(domain_rows: List[Dict[str, Any]], origin_id: str) -> Dict[str, int]:
    mine = [d for d in domain_rows if str(d.get("origin_id")) == str(origin_id)]
    return {"total": len(mine), "verified": sum(1 for d in mine if d.get("dns_verified"))}
