from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService

print("=== 1. ClickHouse Status ===")
ch = ClickHouseService()
if ch.connected:
    try:
        access_count = ch.query_stats("SELECT count() FROM access_logs")
        audit_count = ch.query_stats("SELECT count() FROM security_audit_logs")
        print(f"Status: ONLINE")
        print(f"Table 'access_logs' rows: {access_count[0][0] if access_count else 0}")
        print(f"Table 'security_audit_logs' rows: {audit_count[0][0] if audit_count else 0}")
    except Exception as e:
        print(f"Query error: {e}")
else:
    print("Status: OFFLINE")

print("\n=== 2. DynamoDB Status ===")
db = DynamoDBService()
print(f"Table 'waf_users' estimated items: {db.waf_users.item_count}")
print(f"Table 'waf_rules' estimated items: {db.rules_table.item_count}")
print(f"Table 'waf_logs' estimated items: {db.logs_table.item_count}")
print(f"Table 'waf_alerts' estimated items: {db.alerts_table.item_count}")
