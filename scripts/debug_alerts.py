import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../dashboard/backend")))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "../.env"))
load_dotenv(os.path.join(os.path.dirname(__file__), "../dashboard/backend/.env"))

from services.dynamodb_service import DynamoDBService

db = DynamoDBService()
alerts = db.get_all_alerts(10)
print(f"Total alerts returned: {len(alerts)}")
print("Top 10 newest alerts:")
for a in alerts:
    print(f"[{a.get('timestamp')}] ID: {a.get('alert_id')} | IP: {a.get('ip')} | Status: {a.get('status')} | Attack: {a.get('attack_type')}")
