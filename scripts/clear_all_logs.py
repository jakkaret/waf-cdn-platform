import os
import sys
import boto3
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

# 3. Clear DynamoDB waf_logs & waf_alerts if any new items arrived
print("\n[3] Clearing AWS DynamoDB Tables...")
REGION = os.getenv("AWS_REGION", "ap-southeast-1")
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL")

try:
    dynamodb = boto3.resource(
        "dynamodb",
        region_name=REGION,
        aws_access_key_id=AWS_KEY,
        aws_secret_access_key=AWS_SECRET,
        endpoint_url=ENDPOINT_URL,
    )
    for tbl_name in ["waf_logs", "waf_alerts"]:
        table = dynamodb.Table(tbl_name)
        key_names = [k["AttributeName"] for k in table.key_schema]
        projection_expression = ", ".join(f"#{k}" for k in key_names)
        expr_attr_names = {f"#{k}": k for k in key_names}
        
        response = table.scan(
            ProjectionExpression=projection_expression,
            ExpressionAttributeNames=expr_attr_names
        )
        items = response.get("Items", [])
        while "LastEvaluatedKey" in response:
            response = table.scan(
                ProjectionExpression=projection_expression,
                ExpressionAttributeNames=expr_attr_names,
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))
            
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    key = {k: item[k] for k in key_names}
                    batch.delete_item(Key=key)
            print(f"  [+] Deleted {len(items)} items from DynamoDB '{tbl_name}'")
        else:
            print(f"  [+] DynamoDB '{tbl_name}' is already 0 items")
except Exception as e:
    print(f"  [-] DynamoDB clear error: {e}")

print("\n" + "=" * 60)
print("  ALL LOGS IN CLICKHOUSE, DYNAMODB & LOCAL FILES PURGED (0)!")
print("=" * 60)
