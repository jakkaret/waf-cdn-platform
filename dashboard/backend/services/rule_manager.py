import os
import re
import subprocess
import logging
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



_ALLOWED_NGINX_COMMANDS = {
    ("nginx", "-s", "reload"),
    ("nginx", "-t"),
}

CONTAINER_NAME = os.getenv("WAF_CONTAINER_NAME", "waf-nginx")

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
                operator = raw_operator.replace('\\"', '"').replace("\\\\", "\\")
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
        valid, msg = self.validate_rule(rule_data)
        if not valid:
            raise ValueError(msg)

        rule_data["severity"] = rule_data["severity"].upper()
        rule_id = str(rule_data["id"]).replace("custom-", "")
        filename = f"custom-{rule_id}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        safe_operator = escape_secrule_string(rule_data['operator'], '"')
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

    def write_ml_rule(self, rule_id: int, secrule_code: str) -> bool:
        filename = f"ml-{rule_id}.conf"
        header = f"# ------------------------------------------------------------------------\n"
        header += f"# ML Auto-Generated & Approved WAF Rule (ID: {rule_id})\n"
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

    def delete_rule(self, rule_id: str) -> bool:
        filename = f"{rule_id}.conf" if not rule_id.endswith(".conf") else rule_id
        filepath = os.path.join(self.rules_dir, filename)

        if os.path.exists(filepath):
            os.remove(filepath)
            self.test_nginx()
            self.reload_nginx()
            return True
        return False

    def update_rule(self, rule_id: str, rule: dict) -> bool:
        rule["id"] = rule_id.replace("custom-", "")
        valid, msg = self.validate_rule(rule)
        if not valid:
            raise ValueError(msg)

        filename = f"custom-{rule['id']}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Rule {rule_id} ไม่พบในระบบ")

        rule["severity"] = rule["severity"].upper()
        safe_operator = escape_secrule_string(rule['operator'], '"')
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
