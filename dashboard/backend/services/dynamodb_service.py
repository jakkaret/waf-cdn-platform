import boto3
import os
import time
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
TABLE_NAME = "waf_alerts"

# สร้าง resource โดยใช้ credentials จาก .env
dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

table = dynamodb.Table(TABLE_NAME)

def save_alert(user_id: str, alert_id: str, ip: str, url: str, status: str):
    table.put_item(
        Item={
            "user_id": user_id,          # partition key
            "alert_id": alert_id,        # sort key
            "ip": ip,
            "url": url,
            "status": status,
            "timestamp": str(int(time.time()))
        }
    )
    print("✅ Saved alert to DynamoDB")


# สำหรับทดสอบการเชื่อมต่อกับ DynamoDB
def test_connection():
    try:
        table.put_item(
            Item={
                "user_id": "test-user",
                "alert_id": str(int(time.time())),
                "ip": "127.0.0.1",
                "url": "/testattack",
                "status": "403",
                "timestamp": str(int(time.time()))
            }
        )
        print("✅ DynamoDB write success")
    except Exception as e:
        print("❌ DynamoDB write failed:", e)


def get_alerts(limit=5):
    try:
        response = table.scan(Limit=limit)
        items = response.get("Items", [])
        print("✅ DynamoDB read success:", items)
        return items
    except Exception as e:
        print("❌ DynamoDB read failed:", e)
        return []
