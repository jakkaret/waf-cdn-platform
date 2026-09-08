"""Security regression test for the FRP webhook gatekeeper.

Sends synthetic NewProxy events straight at the running dashboard (loopback)
and asserts the domain-scoping decisions. No FRP state is touched.
"""
import json, sys
sys.path.insert(0, "/root/waf_project/dashboard/backend")
import urllib.request
from datetime import timedelta
from services.auth_service import AuthService

URL = "http://127.0.0.1:8000/api/tunnels/frp-hook?op=NewProxy&version=0.1.0"
auth = AuthService()
UID = "9ec589c0-f113-402b-992b-5fb601e08875"


def token_for(domain):
    return auth.create_access_token(
        {"sub": UID, "user_id": UID, "username": "regression-test",
         "domain": domain, "type": "tunnel_token"},
        expires_delta=timedelta(minutes=5),
    )


def new_proxy(target_domain, meta_token=None, run_id="regression-test-run"):
    content = {
        "user": {"user": "", "metas": None, "run_id": run_id},
        "proxy_name": "regression-test",
        "proxy_type": "http",
        "custom_domains": [target_domain],
    }
    if meta_token is not None:
        content["metas"] = {"token": meta_token}
    body = json.dumps({"version": "0.1.0", "op": "NewProxy", "content": content}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# The shared connection secret must not authorize a proxy binding on its own:
# it carries no domain claim, so it cannot show the client owns the hostname.
from api.tunnels import LEGACY_STATIC_TOKEN

CASES = [
    ("own domain, scoped token",        "dvwa.waf-it-kku.online",  token_for("dvwa.waf-it-kku.online"),  False),
    ("shared legacy token, any domain", "juice.waf-it-kku.online", LEGACY_STATIC_TOKEN,                   True),
    ("cross-domain claim",              "juice.waf-it-kku.online", token_for("dvwa.waf-it-kku.online"),  True),
    ("reserved domain claim",           "main.waf-it-kku.online",  token_for("main.waf-it-kku.online"),  True),
    ("no identity at all",              "dvwa.waf-it-kku.online",  None,                                  True),
    ("garbage token",                   "dvwa.waf-it-kku.online",  "not-a-jwt",                           True),
]

failures = 0
for name, domain, tok, want_reject in CASES:
    res = new_proxy(domain, tok)
    got = bool(res.get("reject"))
    ok = got == want_reject
    failures += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name:28s} target={domain:26s} "
          f"reject={got} (want {want_reject}) {res.get('reject_reason','')}")

print("FAILURES:", failures)
sys.exit(1 if failures else 0)
