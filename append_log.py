import json
import os

log_path = "/home/chirachot/seminar/waf_project/logs/cdn/th/access.json"
test_log = {
    "logs": [{
        "cache_status": "TEST", 
        "uri": "/cyber-test-path", 
        "status": "200", 
        "region": "TH", 
        "method": "GET", 
        "remote_addr": "9.9.9.9", 
        "time": "2026-08-17T15:00:00+07:00"
    }]
}

with open(log_path, "a", encoding="utf-8") as f:
    f.write(json.dumps(test_log) + "\n")

print("Appended test log")
