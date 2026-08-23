import json

with open("/root/waf_project/logs/modsecurity/audit.json", "r", encoding="utf-8") as f:
    for line in f:
        try:
            d = json.loads(line)
            msgs = d.get("transaction", {}).get("messages", [])
            if msgs:
                print("=== FOUND MESSAGE ===")
                print(json.dumps(msgs, indent=2))
                break
        except Exception:
            pass
