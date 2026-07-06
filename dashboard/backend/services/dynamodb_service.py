import boto3
import os
import time
import uuid
from dotenv import load_dotenv
from typing import List, Dict, Any
from datetime import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Attr


load_dotenv()

class DynamoDBService:
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-southeast-1")

        self.alerts_table_name = "waf_alerts"
        self.logs_table_name = "waf_logs"
        self.rules_table_name = "waf_rules"
        self.users_table_name = "waf_users"
        endpoint_url = os.getenv("DYNAMODB_ENDPOINT_URL")
        self.dynamodb = boto3.resource(
            "dynamodb",
            region_name=self.region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            endpoint_url=endpoint_url,
        )

        # Initialize tables
        self.alerts_table = self.dynamodb.Table(self.alerts_table_name)
        self.logs_table = self.dynamodb.Table(self.logs_table_name)
        self.rules_table = self.dynamodb.Table(self.rules_table_name)
        self.waf_users = self.dynamodb.Table(self.users_table_name)
    
    def convert_floats(self, obj):
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: self.convert_floats(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.convert_floats(i) for i in obj]
        else:
            return obj
    # LOGS
    def save_log(self, event):
        try:
            event = self.convert_floats(event)

            #เติม primary key ถ้าไม่มี
            event["user_id"] = event.get("user_id", "default-user")
            event["log_id"] = event.get("log_id", str(uuid.uuid4()))

            event["timestamp"] = event.get("timestamp", int(time.time()))
            event["alert"] = event.get("alert", False)
            self.logs_table.put_item(Item=event)
            print("Saved log")

        except Exception as e:
            print("Failed to save log:", e)

    def get_logs(self, limit: int = 10) -> List[Dict]:
        try:
            response = self.logs_table.scan(Limit=limit)
            return response.get("Items", [])
        except Exception as e:
            print("Failed to fetch logs:", e)
            return []

    def get_cdn_logs(self, limit: int = 500, region: str = "ALL") -> List[Dict]:
        """
        [Q2 FIX] ดึง CDN logs โดย filter source='cdn' ที่ DynamoDB level
        แทนการดึง 2000 rows มา filter ใน Python application memory
        """
        try:
            filter_expr = Attr("source").eq("cdn")
            if region and region.upper() != "ALL":
                filter_expr = filter_expr & Attr("region").eq(region.upper())

            response = self.logs_table.scan(
                FilterExpression=filter_expr,
                Limit=limit,
            )
            items = response.get("Items", [])
            items.sort(key=lambda x: int(x.get("timestamp", 0)), reverse=True)
            return items
        except Exception as e:
            print("Failed to fetch CDN logs:", e)
            return []

    # ALERTS
    def save_alert(
        self,
        user_id: str,
        alert_id: str,
        ip: str,
        url: str,
        status: str,
        message: str,
    ) -> bool:
        
        #บันทึก alert ที่จำเป็นลง DynamoDB (waf_alerts)
        
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
            print("Saved alert")
            return True
        except Exception as e:
            print("Failed to save alert:", e)
            return False


    def get_unalerted_403_logs(self):
        try:
            response = self.logs_table.scan(
                FilterExpression=Attr("status").eq(403) & Attr("alert").eq(False)
            )
            return response.get("Items", [])
        except Exception as e:
            print("Failed to fetch 403 logs:", e)
            return []

    def mark_log_alerted(self, user_id, timestamp):
        try:
            self.logs_table.update_item(
                Key={
                    "user_id": user_id,
                    "timestamp": timestamp
                },
                UpdateExpression="SET alert = :val",
                ExpressionAttributeValues={
                    ":val": True
                }
            )
            print("Marked as alerted:", timestamp)
        except Exception as e:
            print("Failed to update alert flag:", e)


    # TEST CONNECTION
    # def test_connection(self) -> bool:
    #     try:
    #         self.alerts_table.put_item(
    #             Item={
    #                 "user_id": "test-user",
    #                 "alert_id": str(int(time.time())),
    #                 "ip": "127.0.0.1",
    #                 "url": "/healthcheck",
    #                 "status": "200",
    #                 "timestamp": datetime.now().isoformat() + "Z",  # ใช้ ISO format
    #             }
    #         )
    #         print("✅ DynamoDB connection OK")
    #         return True
    #     except Exception as e:
    #         print("❌ DynamoDB connection failed:", e)
    #         return False

# ตัวอย่างการใช้งาน / Quick test (python3 -m services.dynamodb_service)
if __name__ == "__main__":
    db = DynamoDBService()

    # [Q8 FIX] เดิมเรียก db.get_alerts() ซึ่งไม่มีใน class → crash
    # แก้เป็น get_logs() และ get_unalerted_403_logs() ที่มีอยู่จริง
    print("=== Recent Logs ===")
    print(db.get_logs(limit=5))

    print("=== Unalerted 403 Logs ===")
    print(db.get_unalerted_403_logs())

