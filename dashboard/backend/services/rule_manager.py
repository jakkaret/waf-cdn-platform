import os
import re
import subprocess
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

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
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            variable = operator = severity = "N/A"
            msg = "N/A"

            sec_rule_match = re.search(
                r'SecRule\s+(\S+)\s+"([^"]+)"\s+\\\s*"([^"]+)"',
                content,
                re.DOTALL
            )

            if sec_rule_match:
                variable = sec_rule_match.group(1)
                operator = sec_rule_match.group(2)
                actions = sec_rule_match.group(3)

                sev_match = re.search(r"severity:([A-Za-z]+)", actions)
                if sev_match:
                    severity = sev_match.group(1).upper()

                msg_match = re.search(r"msg:'([^']+)'", actions)
                if msg_match:
                    msg = msg_match.group(1)

            rules.append({
                "id": filename.replace(".conf", ""),
                "variable": variable,
                "operator": operator,
                "severity": severity,
                "message": msg
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

        # 4. Severity
        sev = str(rule.get("severity", "")).upper()
        if sev not in SEVERITY_MAP:
            return False, "Severity ไม่ถูกต้อง (ต้องเป็น CRITICAL, HIGH, MEDIUM, หรือ LOW)"
        rule["severity"] = sev

        # 5. Message
        if not rule.get("message"):
            return False, "Message ห้ามว่าง"

        return True, "OK"

    def add_rule(self, rule_data: Dict) -> bool:
        valid, msg = self.validate_rule(rule_data)
        if not valid:
            raise ValueError(msg)

        rule_data["severity"] = rule_data["severity"].upper()
        rule_id = str(rule_data["id"]).replace("custom-", "")
        filename = f"custom-{rule_id}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        safe_operator = str(rule_data['operator']).replace('"', '\\"')
        safe_message = str(rule_data['message']).replace("'", "\\'")
        modsec_sev = SEVERITY_MAP.get(rule_data["severity"], "CRITICAL")

        rule_text = (
            f"# Custom Rule {rule_id}\n"
            f"SecRule {rule_data['variable']} \"{safe_operator}\" \\\n"
            f"\"id:{rule_id},phase:2,deny,status:403,"
            f"severity:{modsec_sev},log,msg:'{safe_message}'\"\n"
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
        safe_operator = str(rule['operator']).replace('"', '\\"')
        safe_message = str(rule['message']).replace("'", "\\'")
        modsec_sev = SEVERITY_MAP.get(rule["severity"], "CRITICAL")

        rule_text = (
            f"# Custom Rule {rule['id']}\n"
            f"SecRule {rule['variable']} \"{safe_operator}\" \\\n"
            f"\"id:{rule['id']},phase:2,deny,status:403,"
            f"severity:{modsec_sev},log,msg:'{safe_message}'\"\n"
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)

        self.test_nginx()
        self.reload_nginx()
        return True
