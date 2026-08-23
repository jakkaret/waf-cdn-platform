from services.clickhouse_service import ClickHouseService

ch = ClickHouseService()
if ch.connected:
    rows = ch.client.query("SELECT DISTINCT status_code, count() FROM access_logs GROUP BY status_code ORDER BY count() DESC").result_rows
    print("=== DISTINCT STATUS CODES IN CLICKHOUSE ===")
    for r in rows:
        print(f"Status {r[0]}: {r[1]:,} logs")
