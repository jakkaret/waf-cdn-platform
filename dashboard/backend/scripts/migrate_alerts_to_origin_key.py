#!/usr/bin/env python3
"""Migrate waf_alerts to a key that actually identifies an owner.

WHY
---
waf_alerts is keyed (user_id HASH, alert_id RANGE) and the only writer,
services/telegram_listener.py, has always written the constant
"default-user" as user_id. So the partition key identifies nothing: every
alert in the system lives in one partition, and tenant isolation has to be
re-decided in Python on every read (api/ai_summary.py's
_visible_alerts_for_user, over a full-table scan behind a 5s cache).

Commit 937fc4f closed the actual leak -- alerts now carry an origin_id
resolved exactly at write time, and reads match on it -- so this migration
is no longer a security fix. What it buys is structural: reads become
per-origin queries instead of a scan-and-filter, and the key stops lying.

WHAT IT DOES
------------
1. Creates waf_alerts_v2, keyed (origin_id HASH, alert_id RANGE),
   PAY_PER_REQUEST.
2. Copies every row from waf_alerts. Rows with no origin_id get one
   resolved from their captured Host via waf_domains' domain_name-index;
   anything still unresolvable is written to the sentinel partition
   "unattributed" (direct-to-IP hits and scanner Hosts -- 7 of 8 rows at
   the time this was written). Those stay admin-only, exactly as they are
   today.
3. Verifies the copy row-for-row and prints a summary.

It does NOT switch the application over. waf_alerts is left untouched, so
this is reversible by deleting waf_alerts_v2 and changing nothing else.

AFTER RUNNING
-------------
Switch services/telegram_listener.py to write alerts_v2_table and
api/ai_summary.py's _visible_alerts_for_user to query per visible
origin_id (plus "unattributed" for admins) instead of
db.get_all_alerts(). Keep reading waf_alerts until you are satisfied, then
retire it.

Run from dashboard/backend with the venv active:
    python scripts/migrate_alerts_to_origin_key.py --dry-run
    python scripts/migrate_alerts_to_origin_key.py --apply
"""
import argparse
import os
import sys

import boto3
from dotenv import load_dotenv, find_dotenv

SOURCE_TABLE = "waf_alerts"
TARGET_TABLE = "waf_alerts_v2"
UNATTRIBUTED = "unattributed"


def _clients():
    load_dotenv(find_dotenv())
    load_dotenv(os.path.join(os.path.dirname(__file__), "../../../.env"))
    region = os.getenv("AWS_REGION", "ap-southeast-1")
    kwargs = {
        "region_name": region,
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
    }
    endpoint = os.getenv("DYNAMODB_ENDPOINT_URL")
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client("dynamodb", **kwargs), boto3.resource("dynamodb", **kwargs)


def _scan_all(table):
    items, kwargs = [], {}
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        key = resp.get("LastEvaluatedKey")
        if not key:
            return items
        kwargs["ExclusiveStartKey"] = key


def _resolve_origin_id(dynamodb, domain: str) -> str:
    clean = str(domain or "").strip().lower().rstrip(".")
    if ":" in clean and not clean.startswith("["):
        clean = clean.split(":", 1)[0]
    if not clean:
        return ""
    try:
        resp = dynamodb.Table("waf_domains").query(
            IndexName="domain_name-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("domain_name").eq(clean),
        )
        items = resp.get("Items", [])
        return str(items[0].get("origin_id") or "") if items else ""
    except Exception as e:
        print(f"  ! could not resolve {clean}: {e}")
        return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="actually create and copy")
    parser.add_argument("--dry-run", action="store_true", help="report only (default)")
    args = parser.parse_args()
    apply_changes = args.apply and not args.dry_run

    client, dynamodb = _clients()
    source = dynamodb.Table(SOURCE_TABLE)

    rows = _scan_all(source)
    print(f"{SOURCE_TABLE}: {len(rows)} rows")

    planned = []
    for row in rows:
        origin_id = str(row.get("origin_id") or "")
        if not origin_id:
            origin_id = _resolve_origin_id(dynamodb, row.get("domain", ""))
        planned.append((origin_id or UNATTRIBUTED, row))

    attributed = sum(1 for oid, _ in planned if oid != UNATTRIBUTED)
    print(f"  attributed to a real origin: {attributed}")
    print(f"  -> {UNATTRIBUTED} partition:  {len(planned) - attributed}")

    if not apply_changes:
        print("\ndry run -- nothing written. re-run with --apply")
        return 0

    existing = client.list_tables().get("TableNames", [])
    if TARGET_TABLE not in existing:
        print(f"creating {TARGET_TABLE} ...")
        client.create_table(
            TableName=TARGET_TABLE,
            KeySchema=[
                {"AttributeName": "origin_id", "KeyType": "HASH"},
                {"AttributeName": "alert_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "origin_id", "AttributeType": "S"},
                {"AttributeName": "alert_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        client.get_waiter("table_exists").wait(TableName=TARGET_TABLE)
        print("  created")
    else:
        print(f"{TARGET_TABLE} already exists -- copying into it")

    target = dynamodb.Table(TARGET_TABLE)
    with target.batch_writer() as batch:
        for origin_id, row in planned:
            item = dict(row)
            item["origin_id"] = origin_id
            # user_id is kept as a plain attribute: it is no longer a key,
            # but dropping it would lose the (admittedly constant) value
            # every existing row carries.
            batch.put_item(Item=item)

    copied = _scan_all(target)
    print(f"\n{TARGET_TABLE}: {len(copied)} rows after copy")
    if len(copied) != len(rows):
        print("MISMATCH -- source and target row counts differ, investigate before switching over")
        return 1

    source_ids = {str(r.get("alert_id")) for r in rows}
    target_ids = {str(r.get("alert_id")) for r in copied}
    missing = source_ids - target_ids
    if missing:
        print(f"MISSING alert_ids in target: {sorted(missing)[:10]}")
        return 1

    print("every source alert_id is present in the target")
    print(f"\n{SOURCE_TABLE} was not modified. To roll back: delete {TARGET_TABLE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
