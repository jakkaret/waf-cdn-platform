"""Managed (central) ruleset with versions, plus the per-host map that scopes
every rule to the right origin.

How it fits together (all files land in modsecurity/custom-rules, which the
WAF loads after CRS in alphabetical order and control-api bundles to the
edges every few seconds):

  managed-00-hostmap.conf   one rule per origin, matched on the Host header:
                            sets tx.waf_origin_id (used by per-origin rules),
                            the origin's own anomaly threshold when its Owner
                            approved one (services/threshold_proposal_service),
                            and switches off managed rules that are not part
                            of the version that origin is on (ctl:ruleRemoveById)
  managed-05-honeytokens.conf
                            one @pm rule over every honeytoken the deception
                            layer hands out for a verified host; a request
                            that replays one goes back to the deception layer
  managed-10-rules.conf     every managed rule ever published, by ID

Source of truth for the rules is modsecurity/managed-rules/*.conf in git. No
API edits it. publish() is called by the updater loop on a fixed interval (and
by an admin-only "check now"), notices a changed source, validates it and
records a new version in the catalog. Published rules are immutable by ID: a
change is a new ID; an ID that disappears from the source is "retired" in that
version and stays in the published file so origins pinned to an older version
keep it.

Origins choose, per origin, stored on the origin record:
  managed_ruleset_mode    "auto" (default: always the latest version) or
                          "manual" (stay on managed_ruleset_version until an
                          Admin presses Update)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_DIR = Path(os.getenv("MANAGED_RULES_SOURCE_DIR", REPO_ROOT / "modsecurity" / "managed-rules"))
CATALOG_PATH = Path(os.getenv("MANAGED_RULES_CATALOG", Path(__file__).resolve().parents[1] / "data" / "managed_ruleset.json"))
UPDATE_INTERVAL_SECONDS = int(os.getenv("MANAGED_RULES_INTERVAL_SECONDS", "900"))

HOSTMAP_FILE = "managed-00-hostmap.conf"
HONEYTOKEN_FILE = "managed-05-honeytokens.conf"
RULES_FILE = "managed-10-rules.conf"

MANAGED_ID_MIN, MANAGED_ID_MAX = 3_000_000, 3_099_999
HOSTMAP_ID_BASE = 3_100_000          # 3100000 = unmapped-host fallback, +n per origin
MODE_AUTO, MODE_MANUAL = "auto", "manual"

# Anything that changes engine behaviour, reaches outside the request, or
# switches other rules off is not allowed in a managed rule.
_FORBIDDEN = re.compile(
    r"(?i)(ctl:|SecRuleEngine|SecAction|SecRuleRemove|SecRuleUpdate|SecAudit|SecDefaultAction|exec:"
    r"|@inspectFile|FromFile|@rbl|@geoLookup|@gsbLookup|lua|Include\s)"
)
_RULE_START = re.compile(r"^\s*SecRule\s", re.M)
_ID = re.compile(r"\bid:(\d+)")
_ORIGIN_ID_OK = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST_OK = re.compile(r"^[a-z0-9.-]{1,253}$")

from services import deception_content
from services.rule_manager import RULES_LOCK as _lock  # P4.3: one lock for all rule writers


class ManagedRulesetError(ValueError):
    pass


# --------------------------------------------------------------------- source

def _split_rules(text: str) -> List[str]:
    """Split a .conf into SecRule blocks (continuation lines included),
    dropping comments and blank lines."""
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    blocks, cur = [], []
    for line in lines:
        if _RULE_START.match(line) and cur:
            blocks.append("\n".join(cur))
            cur = []
        cur.append(line.rstrip())
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def load_source(source_dir: Optional[Path] = None) -> Dict[int, str]:
    """Rules in the source directory, by ID. Raises ManagedRulesetError on
    anything that must not be published."""
    source_dir = source_dir if source_dir is not None else SOURCE_DIR  # see load_catalog's comment on late binding
    rules: Dict[int, str] = {}
    for path in sorted(Path(source_dir).glob("*.conf")):
        for block in _split_rules(path.read_text(encoding="utf-8")):
            if not _RULE_START.match(block):
                raise ManagedRulesetError(f"{path.name}: only SecRule directives are allowed")
            if _FORBIDDEN.search(block):
                raise ManagedRulesetError(f"{path.name}: forbidden directive/action in: {block[:80]}")
            ids = _ID.findall(block)
            if len(ids) != 1:
                raise ManagedRulesetError(f"{path.name}: each rule needs exactly one id (chains are not allowed)")
            rid = int(ids[0])
            if not MANAGED_ID_MIN <= rid <= MANAGED_ID_MAX:
                raise ManagedRulesetError(f"{path.name}: id {rid} outside {MANAGED_ID_MIN}-{MANAGED_ID_MAX}")
            if rid in rules:
                raise ManagedRulesetError(f"{path.name}: duplicate id {rid}")
            rules[rid] = block
    return rules


def _msg(block: str) -> str:
    m = re.search(r"msg:'((?:[^'\\]|\\.)*)'", block)
    return m.group(1) if m else ""


def _severity(block: str) -> str:
    m = re.search(r"severity:'?([A-Z]+)", block)
    return m.group(1) if m else ""


# -------------------------------------------------------------------- catalog

def _empty_catalog() -> dict:
    return {"versions": [], "rules": {}}


def load_catalog(path: Optional[Path] = None) -> dict:
    # `path: Path = CATALOG_PATH` would look tidier, but a default argument
    # value is evaluated once at function-definition time -- a test (or
    # anything else) monkeypatching the module-level CATALOG_PATH afterward
    # would never be seen by callers that omit the argument. Resolving the
    # module attribute inside the body instead keeps it live.
    path = path if path is not None else CATALOG_PATH
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_catalog()


def _save_catalog(catalog: dict, path: Path = CATALOG_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def latest_version(catalog: dict) -> int:
    return catalog["versions"][-1]["version"] if catalog["versions"] else 0


def publish(source_dir: Optional[Path] = None, catalog_path: Optional[Path] = None, now: Optional[str] = None) -> Optional[dict]:
    """Record a new version if the source changed. Returns the new version
    entry, or None when nothing changed."""
    source_dir = source_dir if source_dir is not None else SOURCE_DIR  # see load_catalog's comment on late binding
    catalog_path = catalog_path if catalog_path is not None else CATALOG_PATH
    with _lock:
        source = load_source(source_dir)
        catalog = load_catalog(catalog_path)
        digest = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        if catalog["versions"] and catalog["versions"][-1]["source_sha256"] == digest:
            return None

        known = catalog["rules"]
        for rid, text in source.items():
            prev = known.get(str(rid))
            if prev and prev["retired_in"] is not None:
                raise ManagedRulesetError(f"rule {rid} was retired in v{prev['retired_in']}; ids are never reused")
            if prev and prev["text"] != text:
                raise ManagedRulesetError(
                    f"rule {rid} changed after it was published; published rules are immutable -- use a new id"
                )

        version = latest_version(catalog) + 1
        active_before = {int(r) for r, v in known.items() if v.get("retired_in") is None}
        added = sorted(set(source) - {int(r) for r in known})
        retired = sorted(active_before - set(source))
        for rid in added:
            known[str(rid)] = {
                "text": source[rid], "introduced_in": version, "retired_in": None,
                "msg": _msg(source[rid]), "severity": _severity(source[rid]),
            }
        for rid in retired:
            known[str(rid)]["retired_in"] = version
        entry = {
            "version": version,
            "published_at": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_sha256": digest,
            "added": added,
            "retired": retired,
        }
        catalog["versions"].append(entry)
        _save_catalog(catalog, catalog_path)
        logger.info("managed ruleset v%s published (+%d / -%d)", version, len(added), len(retired))
        return entry


def rules_for_version(catalog: dict, version: int) -> List[int]:
    """IDs active at `version`: introduced at or before it, not yet retired."""
    out = []
    for rid, r in catalog["rules"].items():
        if r["introduced_in"] <= version and (r["retired_in"] is None or r["retired_in"] > version):
            out.append(int(rid))
    return sorted(out)


def effective_version(origin: dict, catalog: dict) -> int:
    latest = latest_version(catalog)
    if (origin or {}).get("managed_ruleset_mode") == MODE_MANUAL:
        # `or latest` here would silently discard an explicit pin to version
        # 0 (0 is falsy) and fall back to latest -- caught by
        # test_origin_admin_can_pin_to_manual_then_update_to_latest, which
        # pins to 0 (no managed rules at all) and got 1 back instead.
        stored = origin.get("managed_ruleset_version")
        pinned = int(stored) if stored is not None else latest
        return max(0, min(pinned, latest))
    return latest


# -------------------------------------------------------------- file writers

def render_rules_file(catalog: dict) -> str:
    head = "# Generated by services/managed_ruleset.py -- do not edit. Source: modsecurity/managed-rules/\n"
    body = [catalog["rules"][rid]["text"] for rid in sorted(catalog["rules"], key=int)]
    return head + ("\n\n".join(body) + "\n" if body else "")


def _host_regex(hosts: List[str]) -> str:
    # H59: match every spelling nginx routes to the same server block -- any
    # case (t:lowercase on the rule), a trailing dot, a port.
    return "^(?:" + "|".join(re.escape(h) for h in sorted(hosts)) + r")\.?(?::[0-9]+)?$"


def _removals(catalog: dict, version: int) -> List[int]:
    active = set(rules_for_version(catalog, version))
    return sorted(int(r) for r in catalog["rules"] if int(r) not in active)


def _ctl(ids: List[int]) -> str:
    return "".join(f",ctl:ruleRemoveById={i}" for i in ids)


def _threshold(origin: dict) -> str:
    """Per-origin inbound anomaly threshold. This file loads after CRS and
    after 00-modsecurity-override.conf, so in phase 1 it overrides the
    platform value before CRS evaluates blocking in phase 2."""
    value = origin.get("anomaly_threshold")
    if value is None:
        return ""
    value = int(value)
    if not 3 <= value <= 10:
        raise ManagedRulesetError(f"anomaly_threshold {value} out of range for origin {origin.get('id')}")
    return f",setvar:tx.inbound_anomaly_score_threshold={value}"


def render_hostmap(origins: List[dict], hosts_by_origin: Dict[str, List[str]], catalog: dict) -> str:
    """One phase-1 rule per origin that owns verified hosts, then a fallback
    for requests no origin claimed (lab hosts, direct IP): latest version."""
    lines = ["# Generated by services/managed_ruleset.py -- do not edit."]
    n = 0
    for origin in sorted(origins, key=lambda o: str(o.get("id"))):
        oid = str(origin.get("id") or "")
        hosts = [h for h in hosts_by_origin.get(oid, []) if _HOST_OK.match(h)]
        if not hosts or not _ORIGIN_ID_OK.match(oid):
            continue
        n += 1
        version = effective_version(origin, catalog)
        lines.append(
            f'SecRule REQUEST_HEADERS:Host "@rx {_host_regex(hosts)}" '
            f'"id:{HOSTMAP_ID_BASE + n},phase:1,pass,nolog,t:none,t:lowercase,'
            f"setvar:tx.waf_origin_id={oid},setvar:tx.managed_version={version}"
            f'{_threshold(origin)}{_ctl(_removals(catalog, version))}"'
        )
    latest = latest_version(catalog)
    lines.append(
        f'SecRule &TX:waf_origin_id "@eq 0" '
        f'"id:{HOSTMAP_ID_BASE},phase:1,pass,nolog,setvar:tx.managed_version={latest}'
        f'{_ctl(_removals(catalog, latest))}"'
    )
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------- data from DB

def verified_hosts_by_origin(db) -> Tuple[List[dict], Dict[str, List[str]]]:
    """Active origins and the hosts they have proven they own: DNS-verified
    domains and cloudwaf tunnel domains. Unverified domains are left out on
    purpose -- otherwise anyone could add someone else's hostname and have
    their rules applied to that site's traffic. A host claimed by two
    origins is dropped from both and logged."""
    origins = [o for o in db.list_origins() if o.get("status") not in ("archived", "deleted")]
    claims: Dict[str, set] = {}
    for host, oid in db.verified_hostnames_active():
        host = str(host or "").strip().lower().rstrip(".")
        if host and oid:
            claims.setdefault(host, set()).add(str(oid))
    by_origin: Dict[str, List[str]] = {}
    for host, owners in claims.items():
        if len(owners) != 1:
            logger.warning("host %s claimed by %d origins; left out of the host map", host, len(owners))
            continue
        by_origin.setdefault(next(iter(owners)), []).append(host)
    return origins, by_origin


# ------------------------------------------------------------------ apply

def apply(rule_manager, db, catalog_path: Optional[Path] = None) -> bool:
    """Write the rules file and host map into the WAF rules directory, then
    nginx -t and reload. On a failed test the previous files are restored.
    Returns True when something changed."""
    catalog_path = catalog_path if catalog_path is not None else CATALOG_PATH  # see load_catalog's comment on late binding
    with _lock:
        catalog = load_catalog(catalog_path)
        origins, hosts = verified_hosts_by_origin(db)
        wanted = {
            RULES_FILE: render_rules_file(catalog),
            HOSTMAP_FILE: render_hostmap(origins, hosts, catalog),
            HONEYTOKEN_FILE: deception_content.honeytoken_rule(sorted(h for hs in hosts.values() for h in hs)),
        }
        rules_dir = Path(rule_manager.rules_dir)
        previous = {}
        changed = False
        for name, text in wanted.items():
            path = rules_dir / name
            old = path.read_text(encoding="utf-8") if path.exists() else None
            previous[name] = old
            if old != text:
                path.write_text(text, encoding="utf-8")
                changed = True
        if not changed:
            return False
        try:
            rule_manager.test_nginx()
            rule_manager.reload_nginx()
        except Exception:
            for name, old in previous.items():
                path = rules_dir / name
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(old, encoding="utf-8")
            raise
        return True


def seed_decoys_for_new_origins(rule_manager, db) -> int:
    """Turn on the universal decoy paths once for every active origin that has
    a verified host and has not been seeded yet, then mark it. Universal decoys
    are paths no real site serves (.env, .git, ...), so this is a safe baseline
    the owner can switch off; the decoys_seeded flag keeps it from re-adding a
    decoy the owner later removed. Existing origins were marked seeded by
    migration 0020, so only origins created afterwards get this."""
    from services.tenant_rules import TenantRuleService
    origins, hosts = verified_hosts_by_origin(db)
    svc = TenantRuleService(rule_manager)
    seeded = 0
    for origin in origins:
        oid = str(origin.get("id") or "")
        if origin.get("decoys_seeded") or not hosts.get(oid):
            continue
        try:
            svc.enable_universal_decoys(oid, {"username": "decoy-seed"})
            db.update_origin(oid, {"decoys_seeded": True})
            seeded += 1
        except Exception:
            logger.exception("failed to seed decoys for origin %s", oid)
    return seeded


# ------------------------------------------------------------------- worker

async def managed_ruleset_worker(rule_manager=None, db=None, interval: int = UPDATE_INTERVAL_SECONDS):
    """Background loop: every `interval` seconds, publish() any change to
    modsecurity/managed-rules/ and, if anything published or the domain/
    origin picture changed since the last tick, apply() it to the WAF. A
    failure in one tick (a bad rule in the source, an nginx -t failure) is
    logged and retried next tick rather than crashing the process."""
    import asyncio

    from services.dynamodb_service import DynamoDBService
    from services.rule_manager import RuleManager

    rule_manager = rule_manager or RuleManager()
    db = db or DynamoDBService()
    logger.info("managed ruleset worker starting (interval=%ss)", interval)
    while True:
        try:
            # publish()/apply() do blocking file I/O, database reads, and a
            # docker-exec'd `nginx -t`/reload -- running them directly on the
            # event loop would stall every other request this process is
            # handling for the duration (same bug class as b8dd3f0's
            # blocking DynamoDB calls in the Telegram dispatcher, since replaced by PostgreSQL).
            await asyncio.to_thread(publish, SOURCE_DIR, CATALOG_PATH)
            await asyncio.to_thread(apply, rule_manager, db, CATALOG_PATH)
            # New origins get the universal decoys turned on once (each toggle
            # writes + reloads, so keep it off the apply() path above).
            await asyncio.to_thread(seed_decoys_for_new_origins, rule_manager, db)
        except Exception:
            logger.exception("managed ruleset worker tick failed")
        await asyncio.sleep(interval)


def status_for_origin(origin: dict, catalog: Optional[dict] = None) -> dict:
    catalog = catalog or load_catalog()
    latest = latest_version(catalog)
    current = effective_version(origin, catalog)
    active = set(rules_for_version(catalog, current))
    rules = [
        {
            "id": int(rid), "message": r.get("msg", ""), "severity": r.get("severity", ""),
            "introduced_in": r["introduced_in"], "retired_in": r["retired_in"],
            "active": int(rid) in active,
        }
        for rid, r in sorted(catalog["rules"].items(), key=lambda kv: int(kv[0]))
    ]
    return {
        "mode": (origin or {}).get("managed_ruleset_mode") or MODE_AUTO,
        "current_version": current,
        "latest_version": latest,
        "update_available": current < latest,
        "versions": catalog["versions"],
        "rules": rules,
    }
