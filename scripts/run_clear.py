import os
import sys
import boto3
from dotenv import load_dotenv

load_dotenv("/root/waf_project/dashboard/backend/.env")
load_dotenv("/root/waf_project/.env")

REGION = os.getenv("AWS_REGION", "ap-southeast-1")
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET = os.getenv("AWS_SECRET_ACCESS_KEY")
ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL")

dynamodb = boto3.resource(
    "dynamodb",
    region_name=REGION,
    aws_access_key_id=AWS_KEY,
    aws_secret_access_key=AWS_SECRET,
    endpoint_url=ENDPOINT_URL,
)

def clear_table(table_name):
    table = dynamodb.Table(table_name)
    key_names = [k["AttributeName"] for k in table.key_schema]
    print(f"[*] Checking '{table_name}' with keys: {key_names}", flush=True)

    projection_expression = ", ".join(f"#{k}" for k in key_names)
    expr_attr_names = {f"#{k}": k for k in key_names}

    items = []
    response = table.scan(
        ProjectionExpression=projection_expression,
        ExpressionAttributeNames=expr_attr_names
    )
    items.extend(response.get("Items", []))

    while "LastEvaluatedKey" in response:
        response = table.scan(
            ProjectionExpression=projection_expression,
            ExpressionAttributeNames=expr_attr_names,
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )
        items.extend(response.get("Items", []))

    total = len(items)
    print(f"[!] Total items in '{table_name}': {total}", flush=True)

    if total == 0:
        return 0

    deleted = 0
    with table.batch_writer() as batch:
        for item in items:
            key = {k: item[k] for k in key_names}
            batch.delete_item(Key=key)
            deleted += 1
            if deleted % 200 == 0 or deleted == total:
                print(f"    -> Deleted {deleted}/{total} items...", flush=True)

    print(f"[SUCCESS] Table '{table_name}' successfully cleared! ({deleted} rows deleted)", flush=True)
    return deleted

if __name__ == "__main__":
    for tbl in ["waf_logs", "waf_alerts"]:
        clear_table(tbl)
