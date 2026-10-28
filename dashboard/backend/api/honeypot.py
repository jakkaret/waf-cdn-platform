"""A site's honeypot: what visitors did inside its decoys (2026-10-28).

Events are stored by api/deception.py (services/honeypot.py builds them) and
grouped into sessions when read. Owner and editors only: a session holds
attacker IPs and request bodies, which a viewer has no use for.

The decoy probe answers one question before a decoy is turned on: does the
real site already serve this path? It asks the origin directly, so it only
runs for direct-mode origins with a public IP (the same rule as a direct
route); a tunnel origin is only reachable through its agent."""
import asyncio
import ipaddress
import logging
import secrets
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.site_access import _audit, ip_service
from db import pool
from services import honeypot
from services.gemini_service import gemini_service
from services.origin_ip_rules import SiteIpRuleError
from services.rbac import get_current_user, require_verified_email, verify_origin_edit_access
from services.tenant_rules import DECOY_PATHS
from services.txn import atomic

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/origins/{origin_id}/honeypot", tags=["honeypot"])

MAX_DAYS = honeypot.EVENT_TTL_DAYS
PROBE_TIMEOUT_SECONDS = 4.0


def _sessions(origin_id: str, days: int):
    import datetime as dt
    since = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=days)
    return honeypot.sessionize(honeypot.fetch_events(origin_id, since))


def _find(origin_id: str, sid: str, days: int) -> dict:
    for s in _sessions(origin_id, days):
        if s["id"] == sid:
            return s
    raise HTTPException(status_code=404, detail="Session not found")


@router.get("/summary")
async def honeypot_summary(days: int = Query(7, ge=1, le=MAX_DAYS),
                           origin: dict = Depends(verify_origin_edit_access)):
    sessions = await asyncio.to_thread(_sessions, origin["id"], days)
    return honeypot.summarize_window(sessions, days)


@router.get("/sessions")
async def honeypot_sessions(days: int = Query(7, ge=1, le=MAX_DAYS), limit: int = Query(200, ge=1, le=1000),
                            origin: dict = Depends(verify_origin_edit_access)):
    sessions = await asyncio.to_thread(_sessions, origin["id"], days)
    return {"sessions": [honeypot.public_session(s) for s in sessions[:limit]], "total": len(sessions)}


@router.get("/sessions/{sid}")
async def honeypot_session(sid: str, days: int = Query(30, ge=1, le=MAX_DAYS),
                           origin: dict = Depends(verify_origin_edit_access)):
    s = await asyncio.to_thread(_find, origin["id"], sid, days)
    return {"session": honeypot.public_session(s, with_events=True)}


def story_input(s: dict) -> dict:
    """What the AI summary sees: the session's structured fields and the
    path of each step. No IPs, no bodies, no hashes."""
    return {
        "tool": s["tool"],
        "duration_seconds": s["duration_seconds"],
        "events": s["events"],
        "stages": s["stages"],
        "furthest_stage": s["max_stage"],
        "mitre": {st: honeypot.STAGE_ATTACK[st][0] for st in s["stages"]},
        "categories": s["categories"],
        "login_attempts": s["login_attempts"],
        "distinct_passwords": s["distinct_passwords"],
        "common_passwords": s["common_passwords"],
        "uploads": [{"name": u["name"], "size": u["size"], "type": u["type"]} for u in s["uploads"]],
        "fake_secrets_served": s["tokens_issued"],
        "fake_secrets_used": s["tokens_replayed"],
        "linked_to_earlier_sessions": len(s.get("linked_from", [])),
        "steps": [{"method": e.get("method", ""), "path": (e.get("path") or "")[:200], "stage": e.get("stage", "")}
                  for e in s["_events"][:40]],
    }


@router.post("/sessions/{sid}/story", dependencies=[Depends(require_verified_email("ai"))])
async def honeypot_story(sid: str, days: int = Query(30, ge=1, le=MAX_DAYS),
                         origin: dict = Depends(verify_origin_edit_access)):
    s = await asyncio.to_thread(_find, origin["id"], sid, days)
    text = await gemini_service.summarize_honeypot_session(story_input(s))
    return {"story": text, "ai": text is not None}


class BlockSessionIn(BaseModel):
    hours: Optional[int] = Field(24, ge=1, le=24 * 365, description="Expire after this many hours; empty = permanent")


@router.post("/sessions/{sid}/block")
async def honeypot_block_session(sid: str, body: BlockSessionIn, days: int = Query(30, ge=1, le=MAX_DAYS),
                                 origin: dict = Depends(verify_origin_edit_access),
                                 current_user: dict = Depends(get_current_user)):
    s = await asyncio.to_thread(_find, origin["id"], sid, days)
    note = f"honeypot session {s['actor_id'][:8]}"

    def run():
        added, skipped = [], []
        for ip in s["ips"]:
            try:
                with atomic():
                    rule = ip_service.add(origin["id"], ip, "block", note, body.hours, current_user)
                    _audit(origin["id"], current_user, "site_ip_rule.add",
                           f"บล็อก IP {rule['ip']} จาก honeypot" + (f" ({body.hours} ชม.)" if body.hours else ""),
                           {"ip": rule["ip"], "action": "block", "hours": body.hours, "note": note,
                            "honeypot_session": sid})
                added.append(rule["ip"])
            except SiteIpRuleError as e:
                skipped.append({"ip": ip, "reason": str(e)})
        return {"added": added, "skipped": skipped}

    return await asyncio.to_thread(run)


# ------------------------------------------------------------------ decoy probe

def _probe_host(origin_id: str) -> Optional[str]:
    row = pool.q1("SELECT lower(rtrim(hostname, '.')) AS host FROM origin_hostnames "
                  "WHERE origin_id = %s::uuid AND dns_verified ORDER BY hostname LIMIT 1", (origin_id,))
    return row["host"] if row else None


def _fetch(client: httpx.Client, url: str, host: str, sni: Optional[str]) -> Optional[int]:
    try:
        extensions = {"sni_hostname": sni} if sni else {}
        return client.get(url, headers={"Host": host, "User-Agent": "waf-decoy-probe/1"},
                          extensions=extensions).status_code
    except httpx.HTTPError:
        return None


def probe_decoy(origin: dict, key: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> dict:
    """Does the real site answer the decoy's path? Compared with a random
    path, so a site that answers 200 to everything (an SPA) is not reported
    as serving every decoy. Advisory only: the answer can be wrong both ways
    (a page behind a login, a firewall that drops our address)."""
    from services.nginx_site_service import direct_upstream_allowed

    meta = DECOY_PATHS[key]
    if origin.get("is_tunnel") or origin.get("connection_mode") != "direct":
        return {"checked": False, "reason": "tunnel",
                "note": "Tunnel origins are reached only through their agent; check the path on your server yourself."}
    ip = str(origin.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"checked": False, "reason": "hostname", "note": "The origin is a hostname, not an IP; it is not probed."}
    if not direct_upstream_allowed(ip):
        return {"checked": False, "reason": "not_public", "note": "The origin is not a public address."}
    try:
        port = int(origin.get("port") or 80)
    except (TypeError, ValueError):
        port = 80
    scheme = str(origin.get("origin_scheme") or "").lower() or ("https" if port == 443 else "http")
    host = _probe_host(origin["id"])
    if not host:
        return {"checked": False, "reason": "no_domain", "note": "No verified domain to send as Host yet."}
    url_host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    base = f"{scheme}://{url_host}:{port}"
    path = meta["path"]
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as client:  # noqa: S501 - reachability only
        decoy = _fetch(client, base + path, host, host if scheme == "https" else None)
        baseline = _fetch(client, f"{base}/{secrets.token_hex(8)}-not-a-page", host, host if scheme == "https" else None)
    if decoy is None:
        return {"checked": False, "reason": "unreachable", "note": "The origin did not answer."}
    # A real page: answers differently from a page that does not exist, and
    # not with "not found". 401/403 count: a login wall is still a real path.
    serves = decoy != baseline and decoy not in (404, 410) and (decoy < 500)
    return {"checked": True, "path": path, "status": decoy, "baseline_status": baseline, "serves_path": serves}


@router.get("/decoys/{key}/probe")
async def honeypot_decoy_probe(key: str, origin: dict = Depends(verify_origin_edit_access)):
    if key not in DECOY_PATHS:
        raise HTTPException(status_code=404, detail="Unknown decoy")
    return await asyncio.to_thread(probe_decoy, origin, key)
