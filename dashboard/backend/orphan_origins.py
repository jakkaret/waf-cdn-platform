"""Report (and optionally clear) origin rows whose owner no longer exists.

Deletes only rows that are BOTH orphaned and not referenced by any domain, so
nothing that is serving traffic can be removed. Anything orphaned but still
referenced is reported for a human to decide.
"""
import sys
sys.path.insert(0, "/root/waf_project/dashboard/backend")
from services.dynamodb_service import DynamoDBService

APPLY = "--apply" in sys.argv
db = DynamoDBService()
users = {u["user_id"] for u in db.waf_users.scan().get("Items", [])}
origins = db.origins_table.scan().get("Items", [])
domains = db.domains_table.scan().get("Items", [])
referenced = {d.get("origin_id") for d in domains}

orphans = [o for o in origins if o.get("admin_user_id") not in users]
print(f"origins {len(origins)} | accounts {len(users)} | orphaned {len(orphans)}")
safe, unsafe = [], []
for o in orphans:
    (unsafe if o["id"] in referenced else safe).append(o)

print(f"\norphaned AND referenced by a domain -- left alone ({len(unsafe)}):")
for o in unsafe:
    doms = [d.get("domain_name") for d in domains if d.get("origin_id") == o["id"]]
    print("  ", o["id"][:8], "|", o.get("label"), "| owner", str(o.get("admin_user_id"))[:8], "| domains", doms)

print(f"\norphaned and unreferenced -- safe to remove ({len(safe)}):")
for o in safe:
    print("  ", o["id"][:8], "|", o.get("label"), "| owner", str(o.get("admin_user_id"))[:8])

if APPLY:
    for o in safe:
        db.origins_table.delete_item(Key={"id": o["id"]})
        print("deleted", o["id"][:8], o.get("label"))
    print(f"\nremoved {len(safe)} orphaned origin rows")
else:
    print("\n(dry run -- pass --apply to delete the unreferenced orphans)")
