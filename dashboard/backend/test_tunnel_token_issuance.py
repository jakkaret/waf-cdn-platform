"""Tunnel-token issuance authorization test (SYSTEM-OPERATIONAL-REQUIREMENTS 10/11).

A tunnel token is a bearer claim over one hostname -- the FRP gatekeeper trusts
its `domain` field -- so issuing one for a domain owned by someone else is a
cross-tenant origin hijack. Both issuing endpoints are checked here, with a
throwaway account that owns nothing.
"""
import json, sys, time, urllib.error, urllib.request

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
OTHER_DOMAIN = "juice.waf-it-kku.online"   # registered to another account
results = []


def call(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode()[:200]}


def check(name, got, want, detail=""):
    ok = got in want
    results.append((ok, name, got, want))
    print(f"[{'PASS' if ok else 'FAIL'}] {name:56s} got={got} want={want} {detail}")


email = f"tokentest-{STAMP}@e2e-test.example.com"
pw = f"TokTest!{STAMP}aA"
call("POST", "/api/auth/register",
     body={"email": email, "username": f"tokentest-{STAMP}", "password": pw})
_, login = call("POST", "/api/auth/login", body={"email": email, "password": pw})
tok = login.get("access_token") or login.get("token")
_, me = call("GET", "/api/auth/me", token=tok)
print("account:", me.get("user_id"), me.get("role"))

st, res = call("GET", f"/api/tunnels/config-generator?domain={OTHER_DOMAIN}&port=3000", token=tok)
check("config-generator for another account's domain", st, {403},
      res.get("detail", "") if st != 200 else "TOKEN ISSUED")

# No domain at all must be a validation prompt, not an authorization failure:
# the endpoint used to default to juice.waf-it-kku.online, which turned the
# Tunnels page into a 403 for every account that does not own that domain.
st, res = call("GET", "/api/tunnels/config-generator", token=tok)
check("config-generator with no domain given", st, {422},
      "validation error" if st == 422 else f"unexpected: {res}")

st, res = call("POST", "/api/tunnels/token", token=tok, body={"domain": OTHER_DOMAIN})
check("POST /token for another account's domain", st, {403}, res.get("detail", ""))

st, res = call("POST", "/api/tunnels/token", token=tok, body={"domain": "main.waf-it-kku.online"})
check("POST /token for a reserved domain", st, {400}, res.get("detail", ""))

unclaimed = f"unclaimed-{STAMP}.example.com"
st, res = call("POST", "/api/tunnels/token", token=tok, body={"domain": unclaimed})
check("POST /token for an unregistered domain (allowed)", st, {200}, unclaimed)

st, _ = call("GET", f"/api/tunnels/config-generator?domain={OTHER_DOMAIN}")
check("config-generator without authentication", st, {401, 403})

if me.get("user_id"):
    sys.path.insert(0, "/root/waf_project/dashboard/backend")
    from services.dynamodb_service import DynamoDBService
    DynamoDBService().waf_users.delete_item(Key={"user_id": me["user_id"]})
    print("cleaned up test account", me["user_id"])

fails = [r for r in results if not r[0]]
print(f"\nRESULT: {len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
