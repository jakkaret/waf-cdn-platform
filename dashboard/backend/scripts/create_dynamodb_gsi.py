import boto3
import time
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

dynamodb = boto3.client('dynamodb', region_name=os.getenv("AWS_REGION", "ap-southeast-1"))

table_name = "waf_users"

print(f"Creating GSIs for {table_name}...")
try:
    dynamodb.update_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "email", "AttributeType": "S"},
            {"AttributeName": "auth_provider", "AttributeType": "S"},
            {"AttributeName": "provider_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "EmailIndex",
                    "KeySchema": [
                        {"AttributeName": "email", "KeyType": "HASH"}
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
                }
            },
            {
                "Create": {
                    "IndexName": "ProviderIndex",
                    "KeySchema": [
                        {"AttributeName": "auth_provider", "KeyType": "HASH"},
                        {"AttributeName": "provider_id", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
                }
            }
        ]
    )
    print("GSI creation initiated. It may take a few minutes to become ACTIVE.")
except Exception as e:
    print(f"Error (may already exist): {e}")
