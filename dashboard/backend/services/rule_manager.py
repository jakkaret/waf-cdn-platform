import os
import re
from typing import List, Dict

class RuleManager:
    def __init__(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        # BASE_DIR = .../dashboard/backend/services

        self.rules_dir = os.path.abspath(
            os.path.join(BASE_DIR, "../../../modsecurity/custom-rules")
        )

        if not os.path.exists(self.rules_dir):
            raise FileNotFoundError(f"Rules dir not found: {self.rules_dir}")
    
    
    def list_rules(self):
        rules = []

        for filename in os.listdir(self.rules_dir):
            if not filename.endswith(".conf"):
                continue

            path = os.path.join(self.rules_dir, filename)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            # --- Parse SecRule ---
            sec_rule_match = re.search(
                r'SecRule\s+(\S+)\s+"([^"]+)"\s+\\\s*"([^"]+)"',
                content,
                re.DOTALL
            )

            variable = operator = severity = "N/A"

            if sec_rule_match:
                variable = sec_rule_match.group(1)
                operator = sec_rule_match.group(2)
                actions = sec_rule_match.group(3)

                sev_match = re.search(r"severity:([A-Z]+)", actions)
                if sev_match:
                    severity = sev_match.group(1)

            rules.append({
                "id": filename.replace(".conf", ""),
                "variable": variable,
                "operator": operator,
                "severity": severity
            })

        return rules
    
    def add_rule(self, rule_data: Dict) -> bool:
        """เพิ่ม rule ใหม่"""
        rule_id = rule_data['id']
        filename = f"custom-{rule_id}.conf"
        
        rule_text = f"""
                    # Custom Rule {rule_id}
                    SecRule {rule_data['variable']} "{rule_data['operator']}" \\
                        "id:{rule_id},\\
                        phase:2,\\
                        deny,\\
                        status:403,\\
                        severity:{rule_data['severity']},\\
                        msg:'{rule_data['message']}'"
                    """
        
        with open(f"{self.rules_dir}/{filename}", 'w') as f:
            f.write(rule_text)
        
        return True
    
    def delete_rule(self, rule_id: str) -> bool:
        #rule
        filename = f"custom-{rule_id}.conf"
        filepath = f"{self.rules_dir}/{filename}"
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False
