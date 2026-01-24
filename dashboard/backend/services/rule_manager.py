import os
import re
from typing import List, Dict

class RuleManager:
    def __init__(self, rules_dir="../nginx/templates/modsecurity.d/rules"):
        self.rules_dir = rules_dir
    
    def list_rules(self) -> List[Dict]:
        """อ่าน rules ทั้งหมด"""
        rules = []
        
        for filename in os.listdir(self.rules_dir):
            if filename.endswith('.conf'):
                with open(f"{self.rules_dir}/{filename}") as f:
                    content = f.read()
                    
                    # Parse ModSecurity rule
                    rule_pattern = r'SecRule\s+(.+?)\s+"(.+?)"\s+"(.+?)"'
                    matches = re.findall(rule_pattern, content, re.MULTILINE)
                    
                    for match in matches:
                        rule = {
                            'file': filename,
                            'variable': match[0],
                            'operator': match[1],
                            'actions': match[2]
                        }
                        
                        # Extract ID
                        id_match = re.search(r'id:(\d+)', match[2])
                        if id_match:
                            rule['id'] = id_match.group(1)
                        
                        # Extract severity
                        sev_match = re.search(r'severity:(\w+)', match[2])
                        if sev_match:
                            rule['severity'] = sev_match.group(1)
                        
                        rules.append(rule)
        
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
        """ลบ rule"""
        filename = f"custom-{rule_id}.conf"
        filepath = f"{self.rules_dir}/{filename}"
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False
