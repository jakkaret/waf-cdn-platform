import os
import sys
import httpx
import jwt
from datetime import datetime, timedelta

# Project root .env
sys.path.insert(0, os.path.dirname(__file__))
from services.auth_service import AuthService

def generate_test_token():
    # Use AuthService to generate a valid JWT token
    auth = AuthService()
    token = auth.create_access_token({
        "sub": "3755f84a-3941-4f22-a9e9-bdb0c7f5436b", # test01 user_id
        "role": "admin",
        "email": "test01@gmail.com"
    })
    return token

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
