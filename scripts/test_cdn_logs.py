import httpx
import uuid
import time

BASE_URL = "http://localhost:8000"

with httpx.Client(base_url=BASE_URL) as client:
    test_email = f"test_{uuid.uuid4()}@example.com"
    test_pwd = "Password123!"
    
    # Use register response directly to get token, to avoid login rate limit
    res = client.post("/api/auth/register", json={
        "email": test_email,
        "username": "testadmin2",
        "password": test_pwd,
        "role": "admin"
    })
    print("Register:", res.status_code)
    token = res.json().get("access_token")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print("Fetching CDN logs...")
    res = client.get("/api/cdn/logs?region=ALL&limit=5", headers=headers)
    print("CDN Logs:", res.status_code)
    if res.status_code == 200:
        logs = res.json().get("logs", [])
        print(f"Found {len(logs)} logs.")
    else:
        print(res.text)

    print("Fetching CDN latency...")
    res = client.get("/api/cdn/latency?region=ALL", headers=headers)
    print("CDN Latency:", res.status_code)
    if res.status_code == 200:
        print("Latency endpoint returned successfully.")
        print(res.text[:100] + "...")
    else:
        print(res.text)
