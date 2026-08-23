from services.dynamodb_service import DynamoDBService
from boto3.dynamodb.conditions import Attr

db = DynamoDBService()
users = db.dynamodb.Table("waf_users").scan(FilterExpression=Attr("telegram_chat_id").exists()).get("Items", [])
print(f"Total Users with Telegram chat_id: {len(users)}")
for u in users:
    print("User:", u.get("email"), "Chat ID:", u.get("telegram_chat_id"))
