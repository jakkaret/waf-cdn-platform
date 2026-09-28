"""Per-origin WAF rules ("custom rules" owned by one origin).

An origin's Admins create them; its Viewers can read them; nobody else can see
them. Each rule is a file in the WAF rules directory,

    tenant-<origin_id>-<rule_id>.conf

holding one JSON metadata comment and one generated SecRule chain. The first
link of the chain only lets the rule fire for requests the host map
(managed-00-hostmap.conf, see services/managed_ruleset.py) attributed to this
origin -- i.e. requests whose Host is one of the origin's verified domains --
so a rule can never touch another tenant's traffic. The tenant never writes
SecRule text: they choose a variable, an operator + value and an action from
fixed lists, and the directive is generated here.

These rules run on the shared WAF (Main and every edge), so input is limited:
whitelisted variables and operators, a length cap, regex ReDoS check, no
control characters, and a per-origin quota.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from services.rule_manager import escape_secrule_message, escape_secrule_string
from services.safe_regex import validate_regex_safety

TENANT_ID_MIN, TENANT_ID_MAX = 2_000_000, 2_999_999
MAX_RULES_PER_ORIGIN = int(os.getenv("TENANT_RULES_PER_ORIGIN", "50"))
MAX_VALUE_LENGTH = 512
MAX_MESSAGE_LENGTH = 200

VARIABLES = {
    "REQUEST_URI": "URL (path + query)",
    "REQUEST_FILENAME": "Path",
    "ARGS": "Query/form parameter values",
    "ARGS_NAMES": "Parameter names",
    "REQUEST_HEADERS": "All request headers",
    "REQUEST_HEADERS:User-Agent": "User-Agent",
    "REQUEST_HEADERS:Referer": "Referer",
    "REQUEST_METHOD": "HTTP method",
    "REMOTE_ADDR": "Client IP",
    "REQUEST_BODY": "Request body",
}
# Available in phase 1, before the body is read (DECEIVE runs there).
PHASE1_VARIABLES = VARIABLES.keys() - {"REQUEST_BODY", "ARGS", "ARGS_NAMES"}
OPERATORS = {"@rx", "@contains", "@streq", "@beginsWith", "@endsWith", "@pm", "@ipMatch"}
ACTIONS = {"BLOCK", "CHALLENGE", "DECEIVE", "LOG"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_SEVERITY_MAP = {"CRITICAL": "CRITICAL", "HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "NOTICE"}
TEMPLATES = {"auto", "path_traversal", "sqli"}

_CONTROL = re.compile(r"[\r\n\x00]")
_ORIGIN_ID_OK = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_FILE = re.compile(r"^tenant-([A-Za-z0-9_-]{1,64})-(\d+)\.conf$")
_lock = threading.Lock()


class TenantRuleError(ValueError):
    pass


def validate(rule: dict) -> dict:
    """Return a cleaned copy of the tenant's input or raise TenantRuleError."""
    variable = str(rule.get("variable") or "").strip()
    if variable not in VARIABLES:
        raise TenantRuleError("variable not allowed")
    operator = str(rule.get("operator") or "").strip()
    op, _, value = operator.partition(" ")
    if op not in OPERATORS:
        raise TenantRuleError(f"operator must be one of {sorted(OPERATORS)}")
    value = value.strip()
    if not value:
        raise TenantRuleError("operator needs a value, e.g. '@contains /admin'")
    if len(value) > MAX_VALUE_LENGTH:
        raise TenantRuleError(f"value longer than {MAX_VALUE_LENGTH} characters")
    message = str(rule.get("message") or "").strip()
    if not message or len(message) > MAX_MESSAGE_LENGTH:
        raise TenantRuleError(f"message is required (max {MAX_MESSAGE_LENGTH} characters)")
    if _CONTROL.search(operator) or _CONTROL.search(message):
        raise TenantRuleError("line breaks and control characters are not allowed")
    if op == "@rx":
        ok, reason = validate_regex_safety(value)
        if not ok:
            raise TenantRuleError(f"unsafe regex: {reason}")
    action = str(rule.get("action") or "BLOCK").strip().upper()
    if action not in ACTIONS:
        raise TenantRuleError(f"action must be one of {sorted(ACTIONS)}")
    if action == "DECEIVE" and variable not in PHASE1_VARIABLES:
        raise TenantRuleError("DECEIVE runs before the body is read; use URL, path, headers, method or client IP")
    severity = str(rule.get("severity") or "HIGH").strip().upper()
    if severity not in SEVERITIES:
        raise TenantRuleError(f"severity must be one of {sorted(SEVERITIES)}")
    template = str(rule.get("deception_template") or "auto").strip().lower()
    if template not in TEMPLATES:
        raise TenantRuleError("unknown deception template")
    return {
        "variable": variable, "operator": f"{op} {value}", "message": message,
        "action": action, "severity": severity, "deception_template": template,
        "enabled": bool(rule.get("enabled", True)),
    }


def render(rule_id: int, origin_id: str, rule: dict) -> str:
    """The .conf text for one rule (metadata comment + SecRule chain)."""
    if not _ORIGIN_ID_OK.match(origin_id):
        raise TenantRuleError("bad origin id")
    sev = _SEVERITY_MAP[rule["severity"]]
    msg = escape_secrule_message(rule["message"])
    tags = f"tag:'tenant-rule',tag:'origin:{origin_id}'"
    head = {
        "BLOCK": f"phase:2,deny,status:403,log",
        "CHALLENGE": f"phase:2,deny,status:401,log,tag:'action:challenge'",
        "DECEIVE": f"phase:1,deny,status:418,log,tag:'action:deceive'"
        + (f",tag:'template:{rule['deception_template']}'" if rule["deception_template"] != "auto" else ""),
        "LOG": "phase:2,pass,log",
    }[rule["action"]]
    meta = json.dumps({"id": rule_id, "origin_id": origin_id, **rule}, ensure_ascii=False)
    lines = [f"# META {meta}"]
    if not rule["enabled"]:
        return "\n".join(lines) + "\n# disabled\n"
    lines.append(
        f'SecRule TX:waf_origin_id "@streq {origin_id}" '
        f'"id:{rule_id},{head},severity:{sev},msg:\'{msg}\',{tags},chain"'
    )
    lines.append(f'    SecRule {rule["variable"]} "{escape_secrule_string(rule["operator"], chr(34))}"')
    return "\n".join(lines) + "\n"


class TenantRuleService:
    """File-backed store. Uses the RuleManager's directory and its nginx
    test/reload so tests and production share one code path."""

    def __init__(self, rule_manager):
        self.rm = rule_manager

    @property
    def dir(self) -> Path:
        return Path(self.rm.rules_dir)

    def _files(self) -> List[Path]:
        return sorted(p for p in self.dir.glob("tenant-*.conf") if _FILE.match(p.name))

    def _read(self, path: Path) -> Optional[dict]:
        first = path.read_text(encoding="utf-8").split("\n", 1)[0]
        if not first.startswith("# META "):
            return None
        try:
            return json.loads(first[len("# META "):])
        except ValueError:
            return None

    def list(self, origin_ids) -> List[dict]:
        wanted = {str(o) for o in origin_ids}
        out = []
        for path in self._files():
            oid = _FILE.match(path.name).group(1)
            if oid in wanted:
                meta = self._read(path)
                if meta:
                    out.append(meta)
        return sorted(out, key=lambda r: r["id"])

    def get(self, origin_id: str, rule_id: int) -> Optional[dict]:
        path = self.dir / f"tenant-{origin_id}-{int(rule_id)}.conf"
        return self._read(path) if path.exists() else None

    def _next_id(self) -> int:
        used = [int(_FILE.match(p.name).group(2)) for p in self._files()]
        nxt = max(used) + 1 if used else TENANT_ID_MIN
        if nxt > TENANT_ID_MAX:
            raise TenantRuleError("tenant rule id range exhausted")
        return nxt

    def _write_and_test(self, path: Path, text: Optional[str]) -> None:
        """Write (or delete, when text is None), nginx -t, reload; restore the
        previous content if the test fails."""
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if text is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(text, encoding="utf-8")
        try:
            self.rm.test_nginx()
            self.rm.reload_nginx()
        except Exception:
            if old is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(old, encoding="utf-8")
            raise

    def create(self, origin_id: str, rule: dict, user: dict) -> dict:
        clean = validate(rule)
        with _lock:
            if len(self.list([origin_id])) >= MAX_RULES_PER_ORIGIN:
                raise TenantRuleError(f"an origin can have at most {MAX_RULES_PER_ORIGIN} rules")
            rid = self._next_id()
            clean.update(created_by=user.get("username") or user.get("user_id"),
                         created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
            self._write_and_test(self.dir / f"tenant-{origin_id}-{rid}.conf", render(rid, origin_id, clean))
        return self.get(origin_id, rid)

    def update(self, origin_id: str, rule_id: int, rule: dict, user: dict) -> dict:
        with _lock:
            current = self.get(origin_id, rule_id)
            if not current:
                raise KeyError(rule_id)
            clean = validate({**current, **rule})
            clean.update(created_by=current.get("created_by"), created_at=current.get("created_at"),
                         updated_by=user.get("username") or user.get("user_id"),
                         updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
            self._write_and_test(self.dir / f"tenant-{origin_id}-{int(rule_id)}.conf", render(int(rule_id), origin_id, clean))
        return self.get(origin_id, rule_id)

    def delete(self, origin_id: str, rule_id: int) -> None:
        with _lock:
            path = self.dir / f"tenant-{origin_id}-{int(rule_id)}.conf"
            if not path.exists():
                raise KeyError(rule_id)
            self._write_and_test(path, None)
