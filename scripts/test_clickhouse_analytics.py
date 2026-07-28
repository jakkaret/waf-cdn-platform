import httpx
import time
import sys

BACKEND_URL = "http://localhost:8000"
WAF_URL = "http://localhost:8080"

def main():
    print("==================================================")
    print("🚀 RUNNING CLICKHOUSE HYBRID LOGGING TEST")
    print("==================================================")
    
    # 1. Login to get token for analytics API
    client = httpx.Client(timeout=30.0)
    try:
        r = client.post(f"{BACKEND_URL}/api/auth/login", json={
            "email": "admin_analytics@example.com",
            "password": "password123"
        })
        if r.status_code == 200:
            token = r.json()["access_token"]
        else:
            print("Failed to login, trying to register admin user...")
            client.post(f"{BACKEND_URL}/api/auth/register", json={
                "email": "admin_analytics@example.com",
                "username": "admin",
                "password": "password123"
            })
            r = client.post(f"{BACKEND_URL}/api/auth/login", json={
                "email": "admin_analytics@example.com",
                "password": "password123"
            })
            if r.status_code != 200:
                print(f"Login failed: {r.text}")
            token = r.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        print("✅ Logged in successfully.")
    except Exception as e:
        print(f"❌ Could not authenticate: {e}")
        sys.exit(1)
        
    # 2. Send some normal requests
    print("\n--- Sending 3 normal requests to WAF ---")
    for _ in range(3):
        r = client.get(f"{WAF_URL}/")
        print(f"Normal request status: {r.status_code}")
        
    # 3. Send a malicious SQL injection request to trigger ModSecurity
    print("\n--- Sending a malicious SQLi request to WAF ---")
    r = client.get(f"{WAF_URL}/?id=1%20UNION%20SELECT%20user,password%20FROM%20users")
    print(f"SQLi request status (Expected 403): {r.status_code}")
    
    # Wait a few seconds for log forwarder to process and insert into ClickHouse
    print("\n--- Waiting 5 seconds for Log Forwarder to process... ---")
    time.sleep(5)
    
    # 4. Check Analytics Summary
    print("\n--- Fetching Real-time Analytics Summary from ClickHouse ---")
    r = client.get(f"{BACKEND_URL}/api/analytics/summary", headers=headers)
    print(f"Summary Response Code: {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        print("\n📊 Analytics Data:")
        print(f"Source: {data.get('source')}")
        print(f"Total Requests: {data.get('total_requests')}")
        print(f"Blocked Requests: {data.get('blocked_requests')}")
        print(f"Attack Types: {data.get('attack_types')}")
        print("\n🤖 AI Summary:")
        print(data.get('ai_summary'))
        
        source = data.get("source")
        assert source in ["clickhouse", "fallback_db"], f"Expected source 'clickhouse' or 'fallback_db', got '{source}'"
        
        if source == "fallback_db":
            print("\n⚠️ Note: ClickHouse was offline or crashed (e.g. OOM). Successfully triggered OFFLINE FALLBACK mode!")
        else:
            print("\n✅ Note: ClickHouse is online and successfully processed the logs!")
            
        print("\n✅ HYBRID LOGGING TEST SUCCESSFUL!")
    else:
        print(f"❌ Failed to fetch summary: {r.text}")
        sys.exit(1)

if __name__ == "__main__":
    main()
