from services.clickhouse_service import ClickHouseService
import datetime
import uuid

ch = ClickHouseService()
print("Connected:", ch.connected)

sample = {
    "request_id": str(uuid.uuid4()),
    "ip": "203.0.113.55",
    "method": "GET",
    "url": "/?id=1%27%20UNION%20SELECT",
    "status": 403,
    "latency_ms": 12.5,
    "user_agent": "Mozilla/5.0",
    "country": "TH",
    "edge_node": "edge-th",
    "alert": True,
    "attack_type": "SQL Injection Detected",
    "rule_id": "942100",
    "datetime": datetime.datetime.utcnow().isoformat() + "Z"
}

res = ch.save_log("access_logs", sample)
print("save_log result:", res)

rows = ch.client.query("SELECT count() FROM access_logs").result_rows
print("Total in access_logs:", rows[0][0])
