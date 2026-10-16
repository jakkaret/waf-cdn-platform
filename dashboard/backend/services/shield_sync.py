"""Keeps the shield's Redis state in line with the database (P2.2, P2.6).

control-api decides CAPTCHA/OTP per host from waf:captcha:domain:<host> and
waf:otp:domain:<host>. Those keys used to be written when an admin saved the
settings and never cleaned up (C1/H39/N11/H36/H37): a domain verified after
OTP was switched on got no OTP, and a removed domain or origin left its key
behind for whoever added the same host next.

reconcile() rebuilds them from the database:
  - waf:shield:hostmap  host -> origin_id of every verified host of an active
    origin (the same set the WAF's managed host map uses). control-api
    ignores a domain key whose origin_id is not the host's owner here.
  - a domain key for every verified host whose origin has a saved config,
    and no domain key for anything else.
It also publishes the rate-limit rules control-api enforces.

It runs after every domain/origin change and on a timer (shield_sync_worker),
so a missed call or a Redis restart is repaired within one interval.
"""
import asyncio
import json
import logging
from typing import Dict

from services import captcha_config, otp_config

logger = logging.getLogger(__name__)

HOSTMAP_KEY = "waf:shield:hostmap"
KINDS = {"captcha": captcha_config, "otp": otp_config}


def _host(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def desired_hostmap(db) -> Dict[str, str]:
    """host -> origin_id for verified hosts of active origins. A host claimed
    by two origins is left out (nobody's config applies to it)."""
    claims: Dict[str, set] = {}
    for host, origin_id in db.verified_hostnames_active():
        host = _host(host)
        if host and origin_id:
            claims.setdefault(host, set()).add(str(origin_id))
    out = {}
    for host, owners in claims.items():
        if len(owners) == 1:
            out[host] = next(iter(owners))
        else:
            logger.warning("shield sync: %s is claimed by %d origins, left out", host, len(owners))
    return out


def _write_hostmap(client, hostmap: Dict[str, str]) -> None:
    pipe = client.pipeline(transaction=True)
    pipe.delete(HOSTMAP_KEY)
    if hostmap:
        pipe.hset(HOSTMAP_KEY, mapping=hostmap)
    pipe.execute()


def reconcile(db) -> Dict[str, int]:
    """Make the hostmap and the per-domain keys match the database. Blocking:
    call from a worker thread. Raises when the database or Redis cannot be
    read, changing nothing."""
    hostmap = desired_hostmap(db)
    client = captcha_config._client()
    summary = {"hosts": len(hostmap), "written": 0, "removed": 0}
    _write_hostmap(client, hostmap)
    for kind, module in KINDS.items():
        origin_configs: Dict[str, dict] = {}
        for origin_id in set(hostmap.values()):
            raw = client.get(module._key_origin(origin_id))
            if raw:
                try:
                    value = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    origin_configs[origin_id] = value
        wanted = {}
        for host, origin_id in hostmap.items():
            if origin_id in origin_configs:
                value = dict(origin_configs[origin_id], origin_id=origin_id, domain=host)
                wanted[module._key_domain(host)] = json.dumps(value, separators=(",", ":"))
        existing = set(client.scan_iter(match=f"waf:{kind}:domain:*", count=500))
        pipe = client.pipeline(transaction=False)
        for key, text in wanted.items():
            if client.get(key) != text:
                pipe.set(key, text)
                summary["written"] += 1
        for key in existing - set(wanted):
            pipe.delete(key)
            summary["removed"] += 1
        pipe.execute()
    try:
        from services.rate_limit_service import RateLimitService
        RateLimitService().publish_rules()
    except Exception as exc:
        logger.warning("shield sync: rate-limit rules not published: %s", exc)
    if summary["written"] or summary["removed"]:
        logger.info("shield sync: %s", summary)
    return summary


def reconcile_quietly(db) -> None:
    try:
        reconcile(db)
    except Exception as exc:
        logger.warning("shield sync failed (the worker retries): %s", exc)


_background_tasks: set = set()


def schedule_reconcile(db) -> None:
    """Best-effort, non-blocking: after a domain or origin change."""
    async def _run():
        await asyncio.to_thread(reconcile_quietly, db)
    try:
        task = asyncio.get_running_loop().create_task(_run())
    except RuntimeError:  # no event loop (a script or a sync test): run inline
        reconcile_quietly(db)
        return
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def shield_sync_worker(db, interval_seconds: int = 60) -> None:
    while True:
        await asyncio.to_thread(reconcile_quietly, db)
        await asyncio.sleep(interval_seconds)
