import boto3
from boto3.dynamodb.conditions import Key
import os
from dotenv import load_dotenv
load_dotenv()

endpoint_url = os.getenv("DYNAMODB_ENDPOINT_URL")
dynamodb = boto3.resource(
    "dynamodb",
    region_name=os.getenv("AWS_REGION", "ap-southeast-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "dummy"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "dummy"),
    endpoint_url=endpoint_url,
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