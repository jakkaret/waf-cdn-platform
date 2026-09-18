"""DynamoDB backup + restore test (SYSTEM-OPERATIONAL-REQUIREMENTS 6).

Exports waf_domains to a JSON file, restores it into a temporary table, compares
item-for-item, then deletes the temporary table. The production table is only
ever read.
"""
import json, sys, time
sys.path.insert(0, "/root/waf_project/dashboard/backend")
from decimal import Decimal
from services.dynamodb_service import DynamoDBService

SRC = "waf_domains"
TMP = "waf_domains_restore_test"
DUMP = "/root/waf_project/backups/waf_domains-restore-test.json"

db = DynamoDBService()
client = db.dynamodb.meta.client


def plain(o):
    if isinstance(o, Decimal):
        return int(o) if o % 1 == 0 else float(o)
    if isinstance(o, dict):
        return {k: plain(v) for k, v in o.items()}
    if isinstance(o, list):
        return [plain(v) for v in o]
    return o


print("1. export")
items = db.domains_table.scan().get("Items", [])
import os
os.makedirs(os.path.dirname(DUMP), exist_ok=True)
with open(DUMP, "w") as f:
    json.dump(plain(items), f, indent=1)
print(f"   {len(items)} items -> {DUMP} ({os.path.getsize(DUMP)} bytes)")

print("2. create temporary table")
key_schema = db.domains_table.key_schema
attr_defs = [a for a in db.domains_table.attribute_definitions
             if a["AttributeName"] in {k["AttributeName"] for k in key_schema}]
try:
    client.create_table(TableName=TMP, KeySchema=key_schema,
                        AttributeDefinitions=attr_defs, BillingMode="PAY_PER_REQUEST")
    client.get_waiter("table_exists").wait(TableName=TMP)
    print("   created", TMP)
except client.exceptions.ResourceInUseException:
    print("   already exists, reusing")

print("3. restore from the exported file")
tmp_table = db.dynamodb.Table(TMP)
restored = json.load(open(DUMP))
with tmp_table.batch_writer() as batch:
    for it in restored:
        batch.put_item(Item=json.loads(json.dumps(it), parse_float=Decimal))
time.sleep(2)

print("4. verify")
back = tmp_table.scan().get("Items", [])
src_by_id = {i["id"]: plain(i) for i in items}
new_by_id = {i["id"]: plain(i) for i in back}
same = src_by_id == new_by_id
print(f"   source items {len(src_by_id)} | restored items {len(new_by_id)} | identical: {same}")
if not same:
    only_src = set(src_by_id) - set(new_by_id)
    only_new = set(new_by_id) - set(src_by_id)
    print("   missing:", only_src, "| extra:", only_new)
    for k in set(src_by_id) & set(new_by_id):
        if src_by_id[k] != new_by_id[k]:
            print("   differs:", k)

print("5. teardown")
client.delete_table(TableName=TMP)
client.get_waiter("table_not_exists").wait(TableName=TMP)
print("   deleted", TMP)
print("\nRESTORE TEST:", "PASS" if same else "FAIL")
sys.exit(0 if same else 1)
