import boto3
from boto3.dynamodb.conditions import Key
import os
from dotenv import load_dotenv
load_dotenv()

dynamodb = boto3.resource(
    "dynamodb",
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

table = dynamodb.Table("waf_logs")

def get_recent_logs(limit=10):
    if limit > 25:
        limit = 25

    response = table.query(
        KeyConditionExpression=Key("user_id").eq("default-user"),
        ScanIndexForward=False,
        Limit=limit
    )

    return response.get("Items", [])