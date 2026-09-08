import os
import sys
import httpx
from datetime import datetime, timedelta

# Project root .env
sys.path.insert(0, os.path.dirname(__file__))
from services.auth_service import AuthService

def generate_test_token():
    """Mint a token for an admin account that actually exists.

    This used to hard-code the user id of a `test01` account that has since been
    deleted, so the request came back 401 "User not found" and the endpoint was
    never reached. Resolving an admin at run time keeps the test pointed at the
    application rather than at stale fixture data.
    """
    from services.dynamodb_service import DynamoDBService

    users = DynamoDBService().waf_users.scan().get("Items", [])
    admins = [u for u in users if str(u.get("role", "")).lower() == "admin"]
    if not admins:
        raise SystemExit("no admin account exists to authenticate as")
    admin = admins[0]
    auth = AuthService()
    return auth.create_access_token({
        "sub": admin["user_id"],
        "user_id": admin["user_id"],
        "username": admin.get("username", "admin"),
        "role": "admin",
        "email": admin.get("email", ""),
    })


def test_api():
    token = generate_test_token()
    print("Generated token:", token[:20] + "...")
    
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    print("Querying /api/system/status...")
    try:
        r = httpx.get("http://localhost:8000/api/system/status", headers=headers, timeout=5.0)
        print("Status code:", r.status_code)
        if r.status_code == 200:
            print("Response JSON:")
            import json
            print(json.dumps(r.json(), indent=2, ensure_ascii=False))
        else:
            print("Error response:", r.text)
    except Exception as e:
        print("HTTP request failed:", e)

if __name__ == "__main__":
    test_api()
