#!/usr/bin/env python3
"""
Tunnel agent watchdog (Trello: "tunnel agent หลุดแล้วไม่ auto-recover").

Runs on Lab (10.198.200.75). frpc (systemd unit `waf-agent`) has been
observed getting stuck in a reconnect retry-loop after a disconnect (seen
twice in one session this project) without ever recovering on its own,
requiring a manual `systemctl restart waf-agent` every time. If that
happens during a demo with nobody watching, the affected origins (dvwa/
juice/bwapp -- whichever this Lab hosts) just silently 404/502 until
someone notices.

Health check design -- an earlier version of this script polled Main's FRP
admin dashboard (:7500) cross-machine. That was verified live 2026-09-20 to
be broken by construction: `ss -tlnp` on Main shows :7500 bound to
127.0.0.1 only (a deliberate prior security fix -- "frps admin bind
loopback", see the "Session 8-9 ก.ย." changelog), so Lab could never
actually reach it. This version instead checks each watched domain's real
public HTTPS endpoint directly, the same way an actual visitor would --
needs no credentials, no cross-machine access, and follows this project's
own established lesson (see the "Definition of Done" board card): "HTTP
200 does not mean the origin is alive -- always cache-bust when checking."

Design:
  - Cache-busted HTTPS GET per watched domain (?_wd=<random>) so an Edge
    cache HIT can't mask a dead tunnel behind a stale 200.
  - Only restarts after `failure_threshold` consecutive failed checks (not
    on the first blip) AND only if `cooldown_seconds` has passed since the
    last restart (prevents a restart-loop if restarting doesn't actually
    fix the underlying cause).
  - State (consecutive failure count, last restart time) persists in a
    small JSON file across invocations, since this runs as a short-lived
    timer invocation, not a long-running daemon.

should_restart() and all_domains_healthy() are pure functions with no I/O
-- unit tested directly, no network/systemctl mocking required. Everything
else here is a thin imperative shell around them.
"""
import argparse
import json
import logging
import os
import secrets
import subprocess
import sys
import time
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("tunnel_agent_watchdog")

# This Lab's own tunneled domains -- what "the tunnel is up" means for this
# specific box. Not every domain on the platform; only the ones this agent
# is responsible for keeping reachable.
WATCHED_DOMAINS = [
    d.strip() for d in os.getenv(
        "WATCHDOG_DOMAINS", "dvwa.waf-it-kku.online,juice.waf-it-kku.online,bwapp.waf-it-kku.online"
    ).split(",") if d.strip()
]
STATE_FILE = os.getenv("WATCHDOG_STATE_FILE", "/var/lib/waf-agent-watchdog/state.json")
FAILURE_THRESHOLD = int(os.getenv("WATCHDOG_FAILURE_THRESHOLD", "3"))
COOLDOWN_SECONDS = float(os.getenv("WATCHDOG_COOLDOWN_SECONDS", "600"))  # 10 minutes
SYSTEMD_UNIT = os.getenv("WATCHDOG_UNIT", "waf-agent")
REQUEST_TIMEOUT = float(os.getenv("WATCHDOG_REQUEST_TIMEOUT", "8.0"))
# A tunnel that's up but WAF-blocking this exact probe would answer 403,
# not fail the connection -- only a transport failure or a gateway/server
# error genuinely indicates the tunnel itself is down.
UNHEALTHY_STATUS_CODES = {502, 503, 504, 522, 523, 524}


def should_restart(
    consecutive_failures: int,
    last_restart_ts: Optional[float],
    now: float,
    failure_threshold: int = FAILURE_THRESHOLD,
    cooldown_seconds: float = COOLDOWN_SECONDS,
) -> bool:
    """No I/O. The only restart-timing decision this watchdog has --
    everything else is fetching inputs for this and acting on its answer."""
    if consecutive_failures < failure_threshold:
        return False
    if last_restart_ts is not None and (now - last_restart_ts) < cooldown_seconds:
        return False
    return True


def all_domains_healthy(results: Dict[str, Optional[int]]) -> bool:
    """No I/O. `results` maps domain -> HTTP status code, or None if the
    request itself failed (timeout/connection refused/DNS failure) --
    both None and a gateway-error status code count as unhealthy."""
    for domain, status_code in results.items():
        if status_code is None or status_code in UNHEALTHY_STATUS_CODES:
            return False
    return True


def load_state(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"consecutive_failures": 0, "last_restart_ts": None}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


def check_domain(domain: str, timeout: float = REQUEST_TIMEOUT) -> Optional[int]:
    """Returns the real HTTP status code, or None if the request itself
    never completed. Cache-busted so a stale Edge cache HIT can't mask a
    dead origin behind a false 200 (this project's own established lesson
    -- see module docstring)."""
    cache_buster = secrets.token_hex(4)
    url = f"https://{domain}/?_wd={cache_buster}"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        return resp.status_code
    except Exception as e:
        logger.warning("Health check for %s failed: %s", domain, e)
        return None


def check_all_domains() -> Dict[str, Optional[int]]:
    return {domain: check_domain(domain) for domain in WATCHED_DOMAINS}


def restart_agent() -> bool:
    try:
        subprocess.run(["systemctl", "restart", SYSTEMD_UNIT], check=True, timeout=30)
        return True
    except Exception as e:
        logger.error("Failed to restart %s: %s", SYSTEMD_UNIT, e)
        return False


def run_once(state_file: str = STATE_FILE) -> int:
    state = load_state(state_file)
    now = time.time()

    results = check_all_domains()

    if all_domains_healthy(results):
        if state["consecutive_failures"] > 0:
            logger.info("All watched domains recovered after %d failed check(s)", state["consecutive_failures"])
        state["consecutive_failures"] = 0
        save_state(state_file, state)
        return 0

    state["consecutive_failures"] += 1
    logger.warning(
        "One or more watched domains unhealthy (streak=%d): %s",
        state["consecutive_failures"], results,
    )

    if should_restart(state["consecutive_failures"], state.get("last_restart_ts"), now):
        logger.warning("Failure threshold reached and cooldown elapsed -- restarting %s", SYSTEMD_UNIT)
        if restart_agent():
            state["last_restart_ts"] = now
            state["consecutive_failures"] = 0  # give the fresh connection a clean streak to prove itself
        else:
            logger.error("Restart attempt failed; will retry next cycle without resetting the streak")

    save_state(state_file, state)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-file", default=STATE_FILE)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sys.exit(run_once(args.state_file))
