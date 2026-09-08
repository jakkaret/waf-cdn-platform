"""Multi-tenant isolation / RBAC regression test (SYSTEM-OPERATIONAL-REQUIREMENTS 11).

Creates two throwaway accounts, has each act on the other's resources through the
real HTTP API, and asserts the server-side decision. All objects it creates are
deleted in the teardown, and it never touches pre-existing rows.
"""
import json, sys, time, urllib.error, urllib.request

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
results, created = [], {"origins": [], "users": []}


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


def check(name, got, want_any, detail=""):
    ok = got in want_any
    results.append((ok, name, got, want_any, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name:52s} got={got} want={want_any} {detail}")
    return ok


def register(tag, role=None):
    payload = {"email": f"isolation-{tag}-{STAMP}@isolation-test.example.com",
               "username": f"isolation-{tag}-{STAMP}", "password": f"Pw!{STAMP}{tag}aA1"}
    if role is not None:
        payload["role"] = role
    st, res = call("POST", "/api/auth/register", body=payload)
    tok = res.get("access_token") or res.get("token")
    if not tok:
        st2, res2 = call("POST", "/api/auth/login",
                         body={"email": payload["email"], "password": payload["password"]})
        tok = res2.get("access_token") or res2.get("token")
    st3, me = call("GET", "/api/auth/me", token=tok)
    if me.get("user_id"):
        created["users"].append(me["user_id"])
    return tok, me


print("=== setup: two independent accounts ===")
tok_a, me_a = register("a")
tok_b, me_b = register("b")
print("  A:", me_a.get("user_id"), me_a.get("role"), "| B:", me_b.get("user_id"), me_b.get("role"))

st, origin_a = call("POST", "/api/origins", token=tok_a,
                    body={"label": f"isolation-test-a-{STAMP}", "ip": "127.0.0.1", "port": 8080})
oid_a = origin_a.get("id")
if oid_a:
    created["origins"].append((oid_a, tok_a))
print("  A origin:", st, oid_a)

print("\n=== A reaching its own resource (must be allowed) ===")
st, _ = call("GET", f"/api/origins/{oid_a}", token=tok_a)
check("A reads A's origin", st, {200})

print("\n=== B reaching A's resources (must be denied) ===")
st, _ = call("GET", f"/api/origins/{oid_a}", token=tok_b)
check("B reads A's origin", st, {403, 404})
st, _ = call("PUT", f"/api/origins/{oid_a}", token=tok_b,
             body={"label": "hijacked-by-b", "ip": "127.0.0.1", "port": 9999})
check("B updates A's origin", st, {403, 404})
st, _ = call("GET", f"/api/origins/{oid_a}/domains", token=tok_b)
check("B lists domains under A's origin", st, {403, 404})
st, _ = call("POST", "/api/domains", token=tok_b,
             body={"origin_id": oid_a, "domain_name": f"b-hijack-{STAMP}.isolation-test.example.com"})
check("B attaches a domain to A's origin", st, {403, 404})
st, _ = call("DELETE", f"/api/origins/{oid_a}", token=tok_b)
check("B deletes A's origin", st, {403, 404})

print("\n=== B's listing must not leak A's rows ===")
st, listing = call("GET", "/api/origins", token=tok_b)
rows = listing if isinstance(listing, list) else listing.get("items", listing.get("origins", []))
leaked = [r for r in rows if isinstance(r, dict) and r.get("id") == oid_a]
check("A's origin absent from B's listing", 0 if not leaked else 1, {0}, f"rows={len(rows)}")

print("\n=== anonymous access (must be rejected) ===")
for path in ("/api/origins", "/api/auth/users", "/api/rules/", "/api/logs/recent"):
    st, _ = call("GET", path)
    check(f"anonymous GET {path}", st, {401, 403})

print("\n=== privilege escalation ===")
st, _ = call("GET", "/api/auth/users", token=tok_b)
check("non-admin lists all users", st, {401, 403})
if me_a.get("user_id"):
    st, _ = call("PUT", f"/api/auth/users/{me_a['user_id']}/role", token=tok_b, body={"role": "admin"})
    check("non-admin promotes another user", st, {401, 403})
    st, _ = call("DELETE", f"/api/auth/users/{me_a['user_id']}", token=tok_b)
    check("non-admin deletes another user", st, {401, 403})

print("\n=== self-service role assignment at registration ===")
tok_c, me_c = register("c", role="admin")
check("self-registered role=admin is not honoured", 0 if me_c.get("role") != "admin" else 1, {0},
      f"role={me_c.get('role')}")

print("\n=== origin lifecycle: a deleted origin must stop being reachable ===")
st, tmp = call("POST", "/api/origins", token=tok_a,
               body={"label": f"lifecycle-test-{STAMP}", "ip": "127.0.0.1", "port": 8081})
tmp_id = tmp.get("id")
st, _ = call("DELETE", f"/api/origins/{tmp_id}", token=tok_a)
check("owner deletes their own origin", st, {200})
st, _ = call("GET", f"/api/origins/{tmp_id}", token=tok_a)
check("deleted origin is no longer readable", st, {404})
st, _ = call("POST", "/api/domains", token=tok_a,
             body={"origin_id": tmp_id, "domain_name": f"gone-{STAMP}.isolation-test.example.com"})
check("no domain can be attached to a deleted origin", st, {404})
st, _ = call("POST", f"/api/origins/{tmp_id}/restore", token=tok_a)
check("restore still reaches the archived origin", st, {200})
st, _ = call("GET", f"/api/origins/{tmp_id}", token=tok_a)
check("restored origin is readable again", st, {200})
if tmp_id:
    created["origins"].append((tmp_id, tok_a))

print("\n=== teardown ===")
for oid, tok in created["origins"]:
    st, _ = call("DELETE", f"/api/origins/{oid}", token=tok)
    print("  deleted origin", oid, "->", st)

# Delete the accounts this run created. There is no self-delete endpoint, and
# leaving them behind would add three live credentials to the users table on
# every run -- the table already carries more stale test accounts than real ones.
if created["users"]:
    sys.path.insert(0, "/root/waf_project/dashboard/backend")
    from services.dynamodb_service import DynamoDBService
    users_table = DynamoDBService().waf_users
    for uid in created["users"]:
        try:
            users_table.delete_item(Key={"user_id": uid})
            print("  deleted account", uid)
        except Exception as exc:
            print("  could not delete account", uid, exc)

fails = [r for r in results if not r[0]]
print(f"\nRESULT: {len(results) - len(fails)}/{len(results)} passed, {len(fails)} failed")
for _, name, got, want, _d in fails:
    print("  FAILED:", name, "got", got, "want", want)
sys.exit(1 if fails else 0)
