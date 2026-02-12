import boto3
import os
import time
import uuid
from dotenv import load_dotenv
from typing import List, Dict, Any
from datetime import datetime

load_dotenv()

class DynamoDBService:
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-southeast-1")

        self.alerts_table_name = "waf_alerts"
        self.logs_table_name = "waf_logs"
        self.rules_table_name = "waf_rules"

        self.dynamodb = boto3.resource(
            "dynamodb",
            region_name=self.region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )

        # Initialize tables
        self.alerts_table = self.dynamodb.Table(self.alerts_table_name)
        self.logs_table = self.dynamodb.Table(self.logs_table_name)
        self.rules_table = self.dynamodb.Table(self.rules_table_name)

   
    # -----------------------------
    # LOGS
    # -----------------------------
    def save_log(self, event: Dict[str, Any]) -> bool:
        try:
            # ถ้าไม่มี log_id → ใช้ค่า test 'mew'
            event["log_id"] = event.get("log_id", "mew")
            # ถ้าไม่มี user_id → ใช้ default
            event["user_id"] = event.get("user_id", "default-user")
            # timestamp ต้องเป็น String (เพราะ schema ของ table เป็น S)
            event["timestamp"] = event.get("timestamp", int(time.time()))
            
            self.logs_table.put_item(Item=event)
            print("✅ Saved log")
            return True
        except Exception as e:
            print("❌ Failed to save log:", e)
            return False


    def get_logs(self, limit: int = 10) -> List[Dict]:
        try:
            response = self.logs_table.scan(Limit=limit)
            return response.get("Items", [])
        except Exception as e:
            print("❌ Failed to fetch logs:", e)
            return []

    # -----------------------------
    # ALERTS
    # -----------------------------
    def save_alert(
        self,
        user_id: str,
        alert_id: str,
        ip: str,
        url: str,
        status: str,
        message: str,
    ) -> bool:
        """
        บันทึก alert ที่จำเป็นลง DynamoDB (waf_alerts)
        """
        try:
            self.alerts_table.put_item(
                Item={
                    "user_id": user_id,
                    "alert_id": alert_id,
                    "ip": ip,
                    "url": url,
                    "status": status,
                    "message": message,
                    "timestamp": datetime.now().isoformat() + "Z",  # String ISO
                }
            )
            print("✅ Saved alert")
            return True
        except Exception as e:
            print("❌ Failed to save alert:", e)
            return False

    def get_alerts(self, limit: int = 10) -> List[Dict]:
        try:
            response = self.alerts_table.scan(Limit=limit)
            return response.get("Items", [])
        except Exception as e:
            print("❌ Failed to fetch alerts:", e)
            return []

    # -----------------------------
    # TEST CONNECTION
    # -----------------------------
    def test_connection(self) -> bool:
        try:
            self.alerts_table.put_item(
                Item={
                    "user_id": "test-user",
                    "alert_id": str(int(time.time())),
                    "ip": "127.0.0.1",
                    "url": "/healthcheck",
                    "status": "200",
                    "timestamp": datetime.now().isoformat() + "Z",  # ใช้ ISO format
                }
            )
            print("✅ DynamoDB connection OK")
            return True
        except Exception as e:
            print("❌ DynamoDB connection failed:", e)
            return False


# -----------------------------
# ตัวอย่างการใช้งาน
# -----------------------------
if __name__ == "__main__":
    db = DynamoDBService()

    db.test_connection()

    db.save_alert(
        user_id="user123",
        alert_id="alert001",
        ip="192.168.1.1",
        url="/login",
        status="403",
        message="SQL Injection detected"
    )

    # db.save_log(
    # {
    #     "ip": logforward,
    #     "method": "POST",
    #     "url": "/login.php",
    #     "status": 403,
    #     "attack_type": "SQL_INJECTION",
    #     "rule_triggered": "SQLI-001",
    #     "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    #     "country": "TH"
    #     # ไม่ต้องใส่ user_id → จะถูกเติมเป็น "default-user"
    #     # ไม่ต้องใส่ log_id → จะถูกเติมเป็น "mew"
    #     # ไม่ต้องใส่ timestamp → จะถูกเติมเป็น str(int(time.time()))
    # }
#)

    print(db.get_logs())
    print(db.get_alerts())
