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
            {"AttributeName": "origin_id", "AttributeType": "S"},
            {"AttributeName": "domain_name", "AttributeType": "S"}
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "origin_id-index",
                "KeySchema": [
                    {"AttributeName": "origin_id", "KeyType": "HASH"}
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            },
            {
                "IndexName": "domain_name-index",
                "KeySchema": [
                    {"AttributeName": "domain_name", "KeyType": "HASH"}
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            }
        ],
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    },
    # NOTE (2026-09-23): this table is keyed by domain NAME, not by a
    # surrogate id -- services/ssl_cert_monitor.py and api/domains.py both
    # do get_item(Key={"id": <domain_name>}). It used to declare a
    # domain_id-index GSI implying an ssl_certs.domain_id -> waf_domains.id
    # foreign key; nothing ever wrote domain_id, so on Main that index sat
    # ACTIVE with ItemCount 0 while still consuming write capacity on every
    # cert write. Dropped here so a fresh install stops creating it. The
    # live index still exists and has to be removed separately:
    #   aws dynamodb update-table --table-name waf_ssl_certs \
    #     --global-secondary-index-updates '[{"Delete":{"IndexName":"domain_id-index"}}]'
    {
        "TableName": "waf_ssl_certs",
        "KeySchema": [
            {"AttributeName": "id", "KeyType": "HASH"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "id", "AttributeType": "S"}
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
