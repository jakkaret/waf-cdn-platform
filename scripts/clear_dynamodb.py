import os
import sys
import boto3
from dotenv import load_dotenv

# Load .env
env_paths = [
    os.path.join(os.path.dirname(__file__), "../.env"),
    os.path.join(os.path.dirname(__file__), "../dashboard/backend/.env"),
    ".env"
]
for p in env_paths:
    if os.path.exists(p):
        load_dotenv(p)

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

def clear_table(table_name: str):
    try:
        table = dynamodb.Table(table_name)
        key_names = [k["AttributeName"] for k in table.key_schema]
        print(f"\n[*] Scanning table '{table_name}' (Keys: {key_names})...")
        
        projection_expression = ", ".join(f"#{k}" for k in key_names)
        expr_attr_names = {f"#{k}": k for k in key_names}
        
        response = table.scan(
            ProjectionExpression=projection_expression,
            ExpressionAttributeNames=expr_attr_names
        )
        items = response.get("Items", [])
        
        while "LastEvaluatedKey" in response:
            response = table.scan(
                ProjectionExpression=projection_expression,
                ExpressionAttributeNames=expr_attr_names,
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))
            
        total_items = len(items)
        if total_items == 0:
            print(f"[+] Table '{table_name}' is already empty (0 items).")
            return 0

        print(f"[!] Found {total_items} items in '{table_name}'. Deleting...")
        deleted_count = 0
        with table.batch_writer() as batch:
            for item in items:
                key = {k: item[k] for k in key_names}
                batch.delete_item(Key=key)
                deleted_count += 1
                if deleted_count % 100 == 0 or deleted_count == total_items:
                    print(f"    -> Deleted {deleted_count}/{total_items} items...")

        print(f"[SUCCESS] Cleared table '{table_name}' ({deleted_count} items removed).")
        return deleted_count

    except Exception as e:
        print(f"[-] Error clearing table '{table_name}': {e}")
        return 0

if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["waf_logs", "waf_alerts"]
    print("=" * 60)
    print(f"  Clearing DynamoDB Tables: {', '.join(targets)}")
    print("=" * 60)
    
    for t in targets:
        clear_table(t)
    
    print("\n[+] All requested tables processed.")
