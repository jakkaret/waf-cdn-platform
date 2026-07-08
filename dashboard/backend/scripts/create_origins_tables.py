import boto3
import os
from dotenv import load_dotenv

# project root .env
load_dotenv(os.path.join(os.path.dirname(__file__), '../../../.env'))

endpoint_url = os.getenv("DYNAMODB_ENDPOINT_URL")
if endpoint_url:
    dynamodb = boto3.client(
        'dynamodb',
        region_name=os.getenv("AWS_REGION", "ap-southeast-1"),
        endpoint_url=endpoint_url,
    )
else:
    dynamodb = boto3.client(
        'dynamodb',
        region_name=os.getenv("AWS_REGION", "ap-southeast-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )

tables_to_create = [
    {
        "TableName": "waf_origins",
        "KeySchema": [
            {"AttributeName": "id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "admin_user_id", "AttributeType": "S"}
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "admin_user_id-index",
                "KeySchema": [
                    {"AttributeName": "admin_user_id", "KeyType": "HASH"}
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            }
        ],
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    },
    {
        "TableName": "waf_domains",
        "KeySchema": [
            {"AttributeName": "id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "origin_id", "AttributeType": "S"}
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "origin_id-index",
                "KeySchema": [
                    {"AttributeName": "origin_id", "KeyType": "HASH"}
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            }
        ],
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    },
    {
        "TableName": "waf_ssl_certs",
        "KeySchema": [
            {"AttributeName": "id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "domain_id", "AttributeType": "S"}
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "domain_id-index",
                "KeySchema": [
                    {"AttributeName": "domain_id", "KeyType": "HASH"}
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            }
        ],
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    }
]

for table in tables_to_create:
    print(f"Creating table {table['TableName']}...")
    try:
        dynamodb.create_table(**table)
        print(f"Table {table['TableName']} created successfully.")
    except Exception as e:
        print(f"Error creating table {table['TableName']} (might already exist): {e}")
