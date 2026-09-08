"""Analytics summary smoke test.

The previous version called the FastAPI handler as a plain function, so its
`Depends(...)` default arrived unresolved and the test died with
"'Depends' object has no attribute 'get'" -- a failure of the test, not of the
application. Going over HTTP exercises the same path the dashboard uses.
"""
import json, sys, urllib.request, urllib.error
sys.path.insert(0, "/root/waf_project/dashboard/backend")
from datetime import timedelta
from services.auth_service import AuthService
from services.dynamodb_service import DynamoDBService

BASE = "http://127.0.0.1:8000"

admins = [u for u in DynamoDBService().waf_users.scan().get("Items", [])
          if str(u.get("role", "")).lower() == "admin"]
if not admins:
    raise SystemExit("no admin account exists to authenticate as")
admin = admins[0]
tok = AuthService().create_access_token(
    {"sub": admin["user_id"], "user_id": admin["user_id"],
     "username": admin.get("username", "admin"), "role": "admin"},
    expires_delta=timedelta(minutes=5))


def get(path):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read()[:200].decode(errors="replace")}


failures = 0
st, res = get("/api/analytics/summary")
print("GET /api/analytics/summary ->", st)
if st != 200:
    failures += 1
    print("  ", res)
else:
    for key in ("source", "total_requests", "allowed_requests", "blocked_requests", "unique_ips"):
        present = key in res
        print(f"  {key:18s} {'present' if present else 'MISSING'}: {res.get(key)}")
        failures += 0 if present else 1
    total, allowed, blocked = (res.get("total_requests", 0), res.get("allowed_requests", 0),
                               res.get("blocked_requests", 0))
    consistent = total >= allowed and total >= blocked
    print(f"  totals consistent (total >= allowed and >= blocked): {consistent}")
    failures += 0 if consistent else 1

print("\nFAILURES:", failures)
sys.exit(1 if failures else 0)
