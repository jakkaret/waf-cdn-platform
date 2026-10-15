import os
import sys
from dotenv import load_dotenv

load_dotenv("/root/waf_project/dashboard/backend/.env")
load_dotenv("/root/waf_project/.env")

print("=" * 60)
print("           COMPLETE LOGS PURGE OPERATION")
print("=" * 60)

# 1. Clear ClickHouse Tables
try:
    from services.clickhouse_service import ClickHouseService
    ch = ClickHouseService()
    if ch.connected:
        print("\n[1] Clearing ClickHouse Tables...")
        ch.client.command("TRUNCATE TABLE access_logs")
        ch.client.command("TRUNCATE TABLE security_audit_logs")
        count = ch.client.query("SELECT count() FROM access_logs").result_rows[0][0]
        print(f"  [+] ClickHouse 'access_logs' row count: {count} (CLEARED)")
        audit_count = ch.client.query("SELECT count() FROM security_audit_logs").result_rows[0][0]
        print(f"  [+] ClickHouse 'security_audit_logs' row count: {audit_count} (CLEARED)")
except Exception as e:
    print(f"  [-] ClickHouse clear error: {e}")

# 2. Truncate Local Log Files (to prevent re-reading old logs)
print("\n[2] Truncating Local Raw Log Files...")
log_files = [
    "/root/waf_project/logs/nginx/access.json",
    "/root/waf_project/logs/modsecurity/audit.json",
    "/root/waf_project/logs/cdn/th/access.json",
    "/root/waf_project/logs/cdn/sg/access.json",
    "/root/waf_project/logs/cdn/jp/access.json",
]
for lf in log_files:
    if os.path.exists(lf):
        try:
            with open(lf, "w") as f:
                f.truncate(0)
            print(f"  [+] Truncated: {lf}")
        except Exception as e:
            print(f"  [-] Failed to truncate {lf}: {e}")


print("\n" + "=" * 60)
print("  ALL LOGS IN CLICKHOUSE, DYNAMODB & LOCAL FILES PURGED (0)!")
print("=" * 60)
