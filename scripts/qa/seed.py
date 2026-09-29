"""Create (or reuse) the QA tenant used by tests/integration. Run on Main:

    cd /root/waf_project/dashboard/backend && .venv/bin/python ../../scripts/qa/seed.py

Accounts (platform role viewer, i.e. ordinary tenants), all @qa.waf-it-kku.online:
  qa-admin    Admin of origin "QA qa1" (qa1.waf-it-kku.online -> qa-echo)
  qa-viewer   Viewer of that origin
  qa-stranger Admin of a different origin "QA qa2" (qa2.waf-it-kku.online)
Passwords are random, written only to /root/qa/qa.json (mode 600).
"""
import json
import os
import secrets
import sys
from pathlib import Path

import httpx

API = os.getenv("QA_API", "https://waf-it-kku.online/api")
STATE = Path(os.getenv("QA_STATE", "/root/qa/qa.json"))
ECHO_IP, ECHO_PORT = "172.18.0.250", 8080
DOMAIN = "qa.waf-it-kku.online"

state = json.loads(STATE.read_text()) if STATE.exists() else {"accounts": {}, "origins": {}}
client = httpx.Client(timeout=20)


def token_for(name: str) -> str:
    acct = state["accounts"].get(name)
    if not acct:
        acct = {"email": f"{name}@{DOMAIN}", "username": name.replace("-", "_"), "password": secrets.token_urlsafe(18) + "A1!"}
        r = client.post(f"{API}/auth/register", json={**acct, "role": "viewer"})
        if r.status_code != 200:
            sys.exit(f"register {name} failed: {r.status_code} {r.text[:200]}")
        state["accounts"][name] = acct
        save()
    r = client.post(f"{API}/auth/login", json={"email": acct["email"], "password": acct["password"]})
    if r.status_code != 200:
        sys.exit(f"login {name} failed: {r.status_code} {r.text[:200]}")
    return r.json()["access_token"]


def save():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2))
    os.chmod(STATE, 0o600)


def ensure_origin(key: str, owner_token: str, host: str) -> dict:
    h = {"Authorization": f"Bearer {owner_token}"}
    origin_id = state["origins"].get(key, {}).get("id")
    if origin_id and client.get(f"{API}/origins/{origin_id}", headers=h).status_code != 200:
        origin_id = None
    if not origin_id:
        r = client.post(f"{API}/origins", json={"label": f"QA {key}", "ip": ECHO_IP, "port": ECHO_PORT}, headers=h)
        if r.status_code != 200:
            sys.exit(f"create origin {key}: {r.status_code} {r.text[:200]}")
        origin_id = r.json()["id"]
    domains = client.get(f"{API}/origins/{origin_id}/domains", headers=h).json()
    names = [d.get("domain_name") for d in (domains.get("domains", domains) if isinstance(domains, dict) else domains)]
    if host not in names:
        r = client.post(f"{API}/origins/{origin_id}/domains", json={"domain_name": host}, headers=h)
        if r.status_code != 200:
            sys.exit(f"add domain {host}: {r.status_code} {r.text[:200]}")
    state["origins"][key] = {"id": origin_id, "host": host}
    save()
    return state["origins"][key]


def deploy_route(origin: dict):
    # Mode A route (domains.py doesn't do this yet -- see KNOWN_ISSUES).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "dashboard" / "backend"))
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv())
    from services import nginx_site_service as nss
    nss.deploy_site_route(origin["host"], {"id": origin["id"], "ip": ECHO_IP, "port": ECHO_PORT})


if __name__ == "__main__":
    admin, viewer, stranger = token_for("qa-admin"), token_for("qa-viewer"), token_for("qa-stranger")
    qa1 = ensure_origin("qa1", admin, "qa1.waf-it-kku.online")
    qa2 = ensure_origin("qa2", stranger, "qa2.waf-it-kku.online")
    r = client.post(f"{API}/origins/{qa1['id']}/viewers", json={"email": state["accounts"]["qa-viewer"]["email"]},
                    headers={"Authorization": f"Bearer {admin}"})
    if r.status_code not in (200, 400):
        sys.exit(f"grant viewer: {r.status_code} {r.text[:200]}")
    for o in (qa1, qa2):
        deploy_route(o)
    print(json.dumps({"origins": state["origins"], "accounts": list(state["accounts"])}, indent=2))
