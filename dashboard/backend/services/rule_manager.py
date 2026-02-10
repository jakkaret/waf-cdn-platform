import os
import re
from typing import List, Dict
import subprocess

class RuleManager:
    def __init__(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        # BASE_DIR = .../dashboard/backend/services

        self.rules_dir = os.path.abspath(
            os.path.join(BASE_DIR, "../../../modsecurity/custom-rules")
        )

        if not os.path.exists(self.rules_dir):
            raise FileNotFoundError(f"Rules dir not found: {self.rules_dir}")
        

    def reload_nginx(self):
        try:
            subprocess.run(
                ["docker", "exec", "waf-nginx", "nginx", "-s", "reload"],
                check=True
            )
            print("✅ Nginx reloaded successfully")
        except subprocess.CalledProcessError as e:
            print("❌ Failed to reload nginx:", e)
            raise RuntimeError("Reload nginx failed")
        
    def test_nginx(self):
        try:
            subprocess.run(
                ["docker", "exec", "waf-nginx", "nginx", "-t"],
                check=True
            )
            print("✅ Nginx test passed")
        except subprocess.CalledProcessError as e:
            print("❌ Nginx test failed:", e)
            raise RuntimeError("Nginx test failed")
    
    def list_rules(self):
        rules = []

        for filename in os.listdir(self.rules_dir):
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

                sev_match = re.search(r"severity:([A-Z]+)", actions)
                if sev_match:
                    severity = sev_match.group(1)

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
        # 1. Rule ID ต้องเป็นตัวเลข (หรือ custom-xxx)
        rule_id = rule.get("id", "")
        
        # ถ้าเป็น custom-xxx ให้ตัดคำว่า custom- ออก
        if rule_id.startswith("custom-"):
            rule_id = rule_id.replace("custom-", "")
            
        if not rule_id or not rule_id.isdigit():
            return False, "Rule ID ต้องเป็นตัวเลขเท่านั้น"

        # 2. Variable ต้องเป็นตัวที่ ModSecurity รู้จัก
        allowed_vars = [
            "REQUEST_URI",
            "ARGS",
            "REQUEST_HEADERS",
            "REQUEST_BODY"
        ]
        if rule.get("variable") not in allowed_vars:
            return False, "Variable ไม่ถูกต้อง"

        # 3. Operator ห้ามว่าง
        if not rule.get("operator"):
            return False, "Operator ห้ามว่าง"

        # 4. Severity ต้องอยู่ในระดับที่กำหนด
        allowed_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if rule.get("severity") not in allowed_sev:
            return False, "Severity ไม่ถูกต้อง"

        # 5. Message ห้ามว่าง
        if not rule.get("message"):
            return False, "Message ห้ามว่าง"

        return True, "OK"


    
    def add_rule(self, rule_data: Dict) -> bool:
        valid, msg = self.validate_rule(rule_data)
        if not valid:
            raise ValueError(msg)
        
        rule_data["severity"] = rule_data["severity"].upper()
        rule_id = rule_data["id"]
        filename = f"custom-{rule_id}.conf"

        rule_text = (
            f"# Custom Rule {rule_id}\n"
            f"SecRule {rule_data['variable']} \"{rule_data['operator']}\" \\\n"
            f"\"id:{rule_id},phase:2,deny,status:403,"
            f"severity:{rule_data['severity']},log,msg:'{rule_data['message']}'\"\n"
        )

        with open(os.path.join(self.rules_dir, filename), "w", encoding="utf-8") as f:
            f.write(rule_text)
        self.test_nginx()
        self.reload_nginx()
        return True

    
    def delete_rule(self, rule_id: str) -> bool:
        filename = f"{rule_id}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        if os.path.exists(filepath):
            os.remove(filepath)
            self.test_nginx()
            self.reload_nginx()
            return True
        return False

    def update_rule(self, rule_id: str, rule: dict) -> bool:
        """อัพเดต rule ที่มีอยู่แล้ว"""
        # เพิ่ม id เข้าไปใน rule dict เพื่อ validate
        rule["id"] = rule_id.replace("custom-", "")
        
        # Validate rule
        valid, msg = self.validate_rule(rule)
        if not valid:
            raise ValueError(msg)

        # สร้าง path ของไฟล์
        filename = f"{rule_id}.conf"
        filepath = os.path.join(self.rules_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Rule {rule_id} ไม่พบในระบบ")

        # สร้าง rule text ใหม่
        rule["severity"] = rule["severity"].upper()
        rule_text = (
            f"# Custom Rule {rule['id']}\n"
            f"SecRule {rule['variable']} \"{rule['operator']}\" \\\n"
            f"\"id:{rule['id']},phase:2,deny,status:403,"
            f"severity:{rule['severity']},log,msg:'{rule['message']}'\"\n"
        )

        # เขียนไฟล์ใหม่
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rule_text)
            
        # Test และ Reload Nginx
        self.test_nginx()
        self.reload_nginx()

        return True