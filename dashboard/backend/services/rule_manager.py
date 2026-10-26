import os
import re
import subprocess
import logging
import threading
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def escape_secrule_string(value: str, quote_char: str) -> str:
    """Escape a value for safe embedding inside a ModSecurity SecRule
    quoted field (the operator's double-quoted string, or the msg action's
    single-quoted string).

    ModSecurity's config parser treats backslash as an escape character
    inside quoted strings -- confirmed against the real engine (`nginx -t`
    on waf-nginx, 2026-09-01): a rule written with the old
    value.replace(quote_char, "\\" + quote_char) escaping and a value
    ending "\\'" produced "Expecting an action, got: ..." because the
    pre-existing backslash consumed the escaper's own quote, letting the
    admin's quote close the field early. Escaping backslash first closes
    that gap, the same fix as ClickHouse's escape_like_value().
    """
    return str(value).replace("\\", "\\\\").replace(quote_char, "\\" + quote_char)


def escape_secrule_operator(value: str) -> str:
    """Prepare a rule *operator* (e.g. ``@rx union\\s+select``) for its
    double-quoted SecRule field.

    Unlike escape_secrule_string, backslashes are left INTACT and only the
    field's own double quote is escaped. libmodsecurity 3.0.16 does not
    unescape ``\\\\`` inside an operator string (verified against the engine,
    Known Issue #11), so doubling the backslash made a regex metaclass such as
    ``\\s`` compile as the literal two characters ``\\s`` -- the rule silently
    stopped matching what the admin typed. A backslash directly before the
    closing quote, or at the very end of the value, would still consume the
    escaping quote and let the value break out of its field, so those are
    rejected rather than escaped (the same guard as
    services/tenant_rules.render). Callers surface the ValueError as a 4xx.
    """
    s = str(value)
    if "\r" in s or "\n" in s:
        # A line break would end or split the directive (re-audit 2026-10-17).
        raise ValueError("operator: line breaks are not allowed")
    if s.endswith("\\") or '\\"' in s:
        raise ValueError(
            "operator: a backslash may not directly precede a double quote or end the value"
        )
    return s.replace('"', '\\"')


_CONTROL_CHARS = re.compile(r"[\r\n\x00]")


def escape_secrule_message(value: str) -> str:
    """Escape a message string for safe embedding inside msg:'...' within a
    double-quoted SecRule action directive.

    ModSecurity directives enclose the action list in double quotes ("..."),
    while the msg action encloses its value in single quotes (msg:'...').
    Therefore, safe_message must escape:
    1. Backslashes (\\ -> \\\\) so backslashes do not consume quotes.
    2. Single quotes (' -> \\') so the msg field does not close early.
    3. Double quotes (\" -> \\\") so the outer SecRule action list does not terminate early.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')



# P4.3 (H61): one lock for every writer of the WAF rule directory -- custom,
# ML/CVE, managed, tenant and IP rules all go write -> nginx -t -> reload ->
# rollback under it, so two changes can no longer interleave and roll each
# other back halfway. Re-entrant: a writer may call test/reload inside it.
RULES_LOCK = threading.RLock()

# P4.3 (H60): the rules API may delete only hand-made custom rules.
CUSTOM_RULE_ID_RE = re.compile(r"^custom-\d{1,10}$")

# P4.2 (N16/H57/H58): what an ML/CVE rule may contain before it is written.
_ML_FORBIDDEN_ACTIONS = re.compile(
    r"(?:^|[,\s\"])(?:exec|ctl|chain|allow|pass|setenv|setuid|setsid|setrsc|proxy|redirect|"
    r"append|prepend|xmlns|skip|skipafter|sanitise\w*|t:none,?\s*nolog)\b",
    re.IGNORECASE,
)
_DIRECTIVE_RE = re.compile(r"^\s*(Sec\w+|Include\w*)\b", re.IGNORECASE | re.MULTILINE)
_BAD_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def validate_ml_rule_text(text: str, rule_id: int) -> tuple:
    """Fail closed unless `text` is exactly one SecRule with the allocated id
    that denies, and nothing else (P4.2). ValueError says what is wrong.
    Returns (variables, operator, actions) as written in the rule, quoting
    and escapes untouched."""
    if _BAD_CHARS.search(text):
        raise ValueError("rule contains control characters")
    # Validate exactly what _write_ml_rule writes (re-audit 2026-10-17): no
    # comment lines are dropped first, and every line break must be a
    # backslash continuation, so no line can hide from the checks below.
    body = text.strip("\n")
    if any(line.lstrip().startswith("#") for line in body.splitlines()):
        raise ValueError("generated rules may not contain comment lines")
    if re.search(r"(?<!\\)\n", body):
        raise ValueError("every line break in a generated rule must be a backslash continuation")
    directives = _DIRECTIVE_RE.findall(body)
    if len(directives) != 1 or directives[0] != "SecRule":
        raise ValueError(f"rule must be exactly one SecRule directive, found {directives or 'none'}")
    joined = re.sub(r"\\\n\s*", "", body).strip()
    m = re.match(r'^SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*$', joined, re.DOTALL)
    if not m:
        raise ValueError("rule is not of the form: SecRule VARIABLES \"OPERATOR\" \"ACTIONS\"")
    actions = m.group(3)
    ids = re.findall(r"(?:^|,)\s*id:\s*(\d+)", actions)
    if ids != [str(int(rule_id))]:
        raise ValueError(f"rule id must be the allocated {rule_id}, found {ids}")
    if _ML_FORBIDDEN_ACTIONS.search(actions):
        raise ValueError("rule uses an action that is not allowed for generated rules")
    if not re.search(r"(?:^|,)\s*deny\b", actions) or not re.search(r"(?:^|,)\s*phase:\s*[12]\b", actions):
        raise ValueError("generated rules must deny in phase 1 or 2")
    return m.group(1), m.group(2), actions


# Same shape as services/tenant_rules.py accepts (origin ids are uuids).
_ORIGIN_ID_OK = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Actions a scoped rule keeps on its first link (the one that carries the id,
# phase and disruptive action of a chain) and on the chained link (only the
# transformations, which apply to that link's own variables). Anything else
# is refused instead of guessed at: a rule that cannot be scoped is never
# deployed for every origin by mistake.
_SCOPED_HEAD_ACTIONS = {"id", "phase", "deny", "status", "severity", "log", "nolog", "auditlog",
                        "noauditlog", "msg", "tag", "logdata", "rev", "ver", "maturity", "accuracy"}
_SCOPED_LINK_ACTIONS = {"t"}
# The chained link scope_ml_rule_to_origin writes after the guard's actions:
# its variables and operator, what list_rules reports for a scoped rule.
_CHAINED_LINK_RE = re.compile(r'\s*SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"')


def _split_actions(actions: str) -> List[str]:
    """Split a SecRule action list on the commas outside single-quoted values
    (msg:'a, b'). A backslash and the character after it stay together, so an
    escaped quote (escape_secrule_message) neither opens nor closes a value."""
    parts, current, quoted, i = [], [], False, 0
    while i < len(actions):
        ch = actions[i]
        if ch == "\\" and i + 1 < len(actions):
            current.append(actions[i:i + 2])
            i += 2
            continue
        if ch == "'":
            quoted = not quoted
        elif ch == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    if quoted:
        raise ValueError("rule actions have an unclosed quote")
    parts.append("".join(current).strip())
    return [p for p in parts if p]


def scope_ml_rule_to_origin(text: str, rule_id: int, origin_id: str) -> str:
    """Rewrite an approved ML/CVE rule so it fires only for one origin's traffic.

    The rule is first checked exactly like a global one (validate_ml_rule_text),
    then rebuilt as the same two-link chain services/tenant_rules.py writes:

        SecRule TX:waf_origin_id "@streq <origin_id>" "<id, phase, deny, msg...>,chain"
            SecRule <original variables> "<original operator>" "<original t:...>"

    tx.waf_origin_id is set in phase 1 by managed-00-hostmap.conf for requests
    whose Host is one of the origin's verified domains, so it is known before
    any phase 2 rule runs. A request no origin claimed has no tx.waf_origin_id,
    and a missing variable never matches: the rule stays silent rather than
    applying to everyone. The variables, operator (quoting and escapes as the
    generator wrote them) and transformations are carried over unchanged; a
    rule without transformations gets "t:none" (CRS's SecDefaultAction sets
    none, so the match is the same) because the chained link needs an
    explicit action list -- without one libmodsecurity reads the next file's
    first line as this rule's actions (see services/tenant_rules.render).
    """
    if not _ORIGIN_ID_OK.match(str(origin_id or "")):
        raise ValueError("bad origin id")
    variables, operator, actions = validate_ml_rule_text(text, rule_id)
    head, link = [], []
    for action in _split_actions(actions):
        name = action.split(":", 1)[0].strip().lower()
        if name in _SCOPED_LINK_ACTIONS:
            link.append(action)
        elif name in _SCOPED_HEAD_ACTIONS:
            head.append(action)
        else:
            raise ValueError(f"action '{name}' cannot be scoped to an origin")
    head += ["tag:'ml-rule'", f"tag:'origin:{origin_id}'", "chain"]
    return (f'SecRule TX:waf_origin_id "@streq {origin_id}" \\\n'
            f'    "{",".join(head)}"\n'
            f'    SecRule {variables} "{operator}" "{",".join(link) or "t:none"}"')


_ALLOWED_NGINX_COMMANDS = {
    ("nginx", "-s", "reload"),
    ("nginx", "-t"),
}

CONTAINER_NAME = os.getenv("WAF_CONTAINER_NAME", "waf-nginx")


class NginxConfigError(RuntimeError):
    """`nginx -t` rejected the on-disk config. Reloading would be a silent
    no-op (the master keeps the old config and `nginx -s reload` still exits 0)
    and the next container start would fail, so callers must not treat the
    change as applied (F-037)."""

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "ERROR",
    "MEDIUM": "WARNING",
    "LOW": "NOTICE",
    "WARNING": "WARNING",
    "NOTICE": "NOTICE",
    "INFO": "INFO",
    "ERROR": "ERROR",
}


def _build_secrule_directives(
    rule_id: str,
    action: str,
    severity: str,
    safe_message: str,
    deception_template: Optional[str] = "auto",
) -> str:
    modsec_sev = SEVERITY_MAP.get(severity, "CRITICAL")
    act = (action or "BLOCK").upper()
    tmpl = (deception_template or "auto").lower()

    if act == "DECEIVE":
        directives = f"id:{rule_id},phase:1,deny,status:418,tag:'action:deceive'"
        if tmpl and tmpl != "auto":
            directives += f",tag:'template:{tmpl}'"
        directives += f",severity:{modsec_sev},log,msg:'{safe_message}'"
        return directives
    elif act == "CHALLENGE":
        return (
            f"id:{rule_id},phase:2,deny,status:401,tag:'action:challenge',"
            f"severity:{modsec_sev},log,msg:'{safe_message}'"
        )
    else:  # BLOCK
        return (
            f"id:{rule_id},phase:2,deny,status:403,"
            f"severity:{modsec_sev},log,msg:'{safe_message}'"
        )


# Written by services/settings_service.py (System settings: engine mode,
# paranoia level, anomaly thresholds) -- a SecAction file, not a rule. Listed,
# it showed on the Rules page as a rule with every field "N/A".
SETTINGS_OVERRIDE_FILE = "00-modsecurity-override.conf"


class RuleManager:
    def __init__(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.rules_dir = os.path.abspath(
            os.path.join(BASE_DIR, "../../../modsecurity/custom-rules")
        )
        if not os.path.exists(self.rules_dir):
            raise FileNotFoundError(f"Rules dir not found: {self.rules_dir}")

    def _run_docker_exec(self, nginx_args: tuple) -> None:
        if nginx_args not in _ALLOWED_NGINX_COMMANDS:
            raise ValueError(f"Command {nginx_args!r} is not in allowed whitelist")

        cmd = ["docker", "exec", CONTAINER_NAME, *nginx_args]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('utf-8') if e.stderr else str(e)
            raise RuntimeError(f"Docker command failed: {err_msg}")

    def reload_nginx(self):
        # Validate before every reload (F-037): `nginx -s reload` exits 0 even
        # when the new config is invalid, so without this a broken rule file is
        # reported as applied, silently ignored by the running nginx, and then
        # stops nginx from starting at the next restart.
        try:
            self._run_docker_exec(("nginx", "-t"))
        except RuntimeError as e:
            msg = str(e)
            if "[emerg]" in msg or "test failed" in msg:
                logger.error(f"nginx -t failed, not reloading: {msg}")
                raise NginxConfigError(msg) from e
            logger.error(msg)
            raise
        try:
            self._run_docker_exec(("nginx", "-s", "reload"))
            logger.info("Nginx reloaded successfully")
        except RuntimeError as e:
            logger.error(str(e))
            raise e

    def test_nginx(self):
        try:
            self._run_docker_exec(("nginx", "-t"))
            logger.info("Nginx config test passed")
        except RuntimeError as e:
            logger.error(str(e))
            raise e

    def list_rules(self) -> List[Dict]:
        rules = []
        for filename in sorted(os.listdir(self.rules_dir)):
            if not filename.endswith(".conf"):
                continue
            # managed-*.conf (central ruleset) and tenant-*.conf (per-origin
            # rules) are generated by managed_ruleset.py / tenant_rules.py
            # and read through their own endpoints, not this legacy list.
            if filename.startswith("managed-") or filename.startswith("tenant-"):
                continue
            if filename == SETTINGS_OVERRIDE_FILE:
                continue

            path = os.path.join(self.rules_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except FileNotFoundError:
                continue

            variable = operator = severity = "N/A"
            msg = "N/A"
            action = "BLOCK"
            deception_template = "auto"
            origin_id = ""

            sec_rule_match = re.search(
                r'SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s+\\\s*"((?:[^"\\]|\\.)*)"',
                content,
                re.DOTALL
            )
            if not sec_rule_match:
                sec_rule_match = re.search(
                    r'SecRule\s+(\S+)\s+"([^"]+)"\s+\\\s*"([^"]+)"',
                    content,
                    re.DOTALL
                )

            if sec_rule_match:
                variable = sec_rule_match.group(1)
                raw_operator = sec_rule_match.group(2)
                actions = sec_rule_match.group(3)
                # An ML rule scoped to one origin (scope_ml_rule_to_origin)
                # starts with the TX:waf_origin_id guard; what it matches is
                # the chained link, so report that and the origin. The id,
                # msg, severity and status stay on the guard's action list.
                if variable == "TX:waf_origin_id" and re.search(r"(?:^|,)\s*chain\s*$", actions):
                    link = _CHAINED_LINK_RE.match(content, sec_rule_match.end())
                    if link:
                        oid = re.search(r"tag:'origin:([A-Za-z0-9_-]+)'", actions)
                        origin_id = oid.group(1) if oid else raw_operator.replace("@streq", "", 1).strip()
                        variable, raw_operator = link.group(1), link.group(2)
                # Operators are written with only the double quote escaped
                # (escape_secrule_operator) -- backslashes are left intact, so
                # reversing only \" reconstructs a regex like \s+ correctly.
                operator = raw_operator.replace('\\"', '"')
                actions = sec_rule_match.group(3)

                sev_match = re.search(r"severity:([A-Za-z]+)", actions)
                if sev_match:
                    severity = sev_match.group(1).upper()

                msg_match = re.search(r"msg:'((?:[^'\\]|\\.)*)'", actions)
                if msg_match:
                    msg = (
                        msg_match.group(1)
                        .replace("\\'", "'")
                        .replace('\\"', '"')
                        .replace("\\\\", "\\")
                    )

                # Tier 1: Look for tag:'action:...'
                tag_action_match = re.search(
                    r"tag:['\"]action:([a-zA-Z]+)['\"]", actions, re.IGNORECASE
                )
                if tag_action_match:
                    action = tag_action_match.group(1).upper()
                else:
                    # Tier 2: Infer from status code
                    status_match = re.search(r"status:(\d+)", actions)
                    if status_match:
                        code = status_match.group(1)
                        if code == "418":
                            action = "DECEIVE"
                        elif code == "401":
                            action = "CHALLENGE"
                        elif code == "403":
                            action = "BLOCK"

                # Extract template: tag:'template:...' or tag:'deception_template:...'
                template_match = re.search(
                    r"tag:['\"](?:template|deception_template):([a-zA-Z0-9_-]+)['\"]",
                    actions,
                    re.IGNORECASE,
                )
                if template_match:
                    deception_template = template_match.group(1).lower()

            rules.append({
                "id": filename.replace(".conf", ""),
                "variable": variable,
                "operator": operator,
                "severity": severity,
                "message": msg,
                "action": action,
                "deception_template": deception_template,
                # "" for a rule that runs for every origin.
                "origin_id": origin_id,
            })

        return rules

    def validate_rule(self, rule: Dict):
        # 1. Rule ID ต้องมีตัวเลข
        rule_id = str(rule.get("id", ""))
        clean_id = rule_id.replace("custom-", "")
        if not clean_id or not clean_id.isdigit():
            return False, "Rule ID ต้องเป็นตัวเลขเท่านั้น"

        # 2. Variable
        allowed_vars = [
            "REQUEST_URI",
            "ARGS",
            "REQUEST_HEADERS",
            "REQUEST_BODY"
        ]
        if rule.get("variable") not in allowed_vars:
            return False, "Variable ไม่ถูกต้อง"

        # 3. Operator
        if not rule.get("operator"):
            return False, "Operator ห้ามว่าง"
        # A line break or NUL would end the generated SecRule line early and
        # leave a .conf that fails nginx -t (or smuggles extra directives).
        if _CONTROL_CHARS.search(str(rule.get("operator"))):
            return False, "Operator ห้ามมีตัวขึ้นบรรทัดใหม่หรืออักขระควบคุม"

        # 4. Severity
        sev = str(rule.get("severity", "")).upper()
        if sev not in SEVERITY_MAP:
            return False, "Severity ไม่ถูกต้อง (ต้องเป็น CRITICAL, HIGH, MEDIUM, หรือ LOW)"
        rule["severity"] = sev

        # 5. Message
        if not rule.get("message"):
            return False, "Message ห้ามว่าง"
        if _CONTROL_CHARS.search(str(rule.get("message"))):
            return False, "Message ห้ามมีตัวขึ้นบรรทัดใหม่หรืออักขระควบคุม"

        # 6. Action
        action_val = rule.get("action", "BLOCK")
        if action_val is None or action_val == "":
            action_val = "BLOCK"
        action = str(action_val).strip().upper()
        allowed_actions = {"BLOCK", "CHALLENGE", "DECEIVE"}
        if action not in allowed_actions:
            return False, f"Action ไม่ถูกต้อง (ต้องเป็น {', '.join(sorted(allowed_actions))})"
        rule["action"] = action

        # 7. Deception Template
        tmpl_val = rule.get("deception_template", "auto")
        if tmpl_val is None or tmpl_val == "":
            tmpl_val = "auto"
        template = str(tmpl_val).strip().lower()
        allowed_templates = {"auto", "path_traversal", "sqli", "sql_injection"}
        if template not in allowed_templates:
            return False, f"Deception template ไม่ถูกต้อง (ต้องเป็น {', '.join(sorted(allowed_templates))})"
        rule["deception_template"] = template

        # DECEIVE rules run in phase 1 so they win over CRS's phase-2 anomaly
        # block; the request body has not been read yet at that point, so a
        # REQUEST_BODY rule would silently never match.
        if action == "DECEIVE" and rule.get("variable") == "REQUEST_BODY":
            return False, "DECEIVE ใช้กับ REQUEST_BODY ไม่ได้ (ทำงานใน phase 1 ก่อนอ่าน body) ใช้ REQUEST_URI, ARGS หรือ REQUEST_HEADERS"

        return True, "OK"

    def add_rule(self, rule_data: Dict) -> bool:
        with RULES_LOCK:
            return self._add_rule(rule_data)

    def _add_rule(self, rule_data: Dict) -> bool:
        valid, msg = self.validate_rule(rule_data)
        if not valid:
            raise ValueError(msg)

        rule_data["severity"] = rule_data["severity"].upper()
        rule_id = str(rule_data["id"]).replace("custom-", "")
        filename = f"custom-{rule_id}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        safe_operator = escape_secrule_operator(rule_data['operator'])
        safe_message = escape_secrule_message(rule_data['message'])
        action_directives = _build_secrule_directives(
            rule_id=rule_id,
            action=rule_data.get("action", "BLOCK"),
            severity=rule_data["severity"],
            safe_message=safe_message,
            deception_template=rule_data.get("deception_template", "auto"),
        )

        rule_text = (
            f"# Custom Rule {rule_id}\n"
            f"SecRule {rule_data['variable']} \"{safe_operator}\" \\\n"
            f"\"{action_directives}\"\n"
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)

        try:
            self.test_nginx()
            self.reload_nginx()
        except Exception as e:
            # Clean up failed config so it does not corrupt nginx
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass
            raise e

        return True

    def write_ml_rule(self, rule_id: int, secrule_code: str, origin_id: str = "") -> bool:
        """Write ml-<id>.conf. With an origin_id the rule is scoped to that
        origin (scope_ml_rule_to_origin); without one it applies to every
        origin. The file name is the same either way, so rule sync and the
        edge bundle (every *.conf in the rules directory) are unchanged."""
        # fail closed before anything is written
        if origin_id:
            secrule_code = scope_ml_rule_to_origin(secrule_code, rule_id, origin_id)
        else:
            validate_ml_rule_text(secrule_code, rule_id)
        with RULES_LOCK:
            return self._write_ml_rule(rule_id, secrule_code, origin_id)

    def _write_ml_rule(self, rule_id: int, secrule_code: str, origin_id: str = "") -> bool:
        filename = f"ml-{rule_id}.conf"
        header = f"# ------------------------------------------------------------------------\n"
        header += f"# ML Auto-Generated & Approved WAF Rule (ID: {rule_id})\n"
        if origin_id:
            header += f"# Scoped to origin {origin_id}: fires only for requests the host map attributed to it\n"
        header += f"# ------------------------------------------------------------------------\n"
        rule_text = header + secrule_code + "\n"
        filepath = os.path.join(self.rules_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)

        try:
            self.test_nginx()
            self.reload_nginx()
        except Exception as e:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass
            raise e

        return True

    def delete_custom_rule(self, rule_id: str) -> bool:
        """The rules API: only custom-<number> (P4.3, H60). Managed, tenant,
        ML and IP rule files are removed by their own services."""
        rule_id = str(rule_id)
        if rule_id.endswith(".conf"):
            rule_id = rule_id[:-5]
        if not CUSTOM_RULE_ID_RE.match(rule_id):
            raise ValueError("rule id must look like custom-<number>")
        return self.delete_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        filename = f"{rule_id}.conf" if not rule_id.endswith(".conf") else rule_id
        if "/" in filename or "\\" in filename or filename.startswith("."):
            raise ValueError("invalid rule id")
        filepath = os.path.join(self.rules_dir, filename)

        with RULES_LOCK:
            if not os.path.exists(filepath):
                return False
            with open(filepath, "r", encoding="utf-8") as f:
                previous_text = f.read()
            os.remove(filepath)
            try:
                self.test_nginx()
                self.reload_nginx()
            except Exception:
                # P4.3: another file depended on this one (an id it removes, a
                # data file): put it back rather than leave a config nginx refuses.
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(previous_text)
                raise
            return True

    def update_rule(self, rule_id: str, rule: dict) -> bool:
        with RULES_LOCK:
            return self._update_rule(rule_id, rule)

    def _update_rule(self, rule_id: str, rule: dict) -> bool:
        rule["id"] = rule_id.replace("custom-", "")
        valid, msg = self.validate_rule(rule)
        if not valid:
            raise ValueError(msg)

        filename = f"custom-{rule['id']}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Rule {rule_id} ไม่พบในระบบ")

        rule["severity"] = rule["severity"].upper()
        safe_operator = escape_secrule_operator(rule['operator'])
        safe_message = escape_secrule_message(rule['message'])
        action_directives = _build_secrule_directives(
            rule_id=rule['id'],
            action=rule.get("action", "BLOCK"),
            severity=rule["severity"],
            safe_message=safe_message,
            deception_template=rule.get("deception_template", "auto"),
        )

        rule_text = (
            f"# Custom Rule {rule['id']}\n"
            f"SecRule {rule['variable']} \"{safe_operator}\" \\\n"
            f"\"{action_directives}\"\n"
        )

        with open(filepath, "r", encoding="utf-8") as f:
            previous_text = f.read()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)

        try:
            self.test_nginx()
            self.reload_nginx()
        except Exception:
            # Put the last good rule back: leaving a file nginx rejects breaks
            # every later reload and the next container start.
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(previous_text)
            raise
        return True
