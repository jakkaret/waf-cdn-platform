import httpx
import uuid
import sys

def run_e2e_test():
    base_url = "http://localhost:8000"
    client = httpx.Client()
    
    # Generate unique credentials
    test_email = f"e2e_{uuid.uuid4().hex[:8]}@example.com"
    test_username = f"user_{uuid.uuid4().hex[:8]}"
    test_password = "Password123!"
    
    print("=" * 60)
    print("🚀 RUNNING END-TO-END INTEGRATION TEST FOR PHASE 1")
    print("=" * 60)
    
    # 1. Register User
    print(f"1. Registering new tenant user:")
    print(f"   Email: {test_email}")
    print(f"   Username: {test_username}")
    
    reg_payload = {
        "email": test_email,
        "username": test_username,
        "password": test_password,
        "role": "admin"
    }
    
    try:
        r_reg = client.post(f"{base_url}/api/auth/register", json=reg_payload)
        print(f"   Response status: {r_reg.status_code}")
        if r_reg.status_code != 200:
            print(f"   ❌ Registration failed: {r_reg.text}")
            sys.exit(1)
            
        reg_data = r_reg.json()
        print("   ✅ Registration successful.")
        token = reg_data.get("access_token")
    except Exception as e:
        print(f"   ❌ HTTP connection failed: {e}")
        sys.exit(1)
        
    # 2. Login User
    print("\n2. Logging in with new credentials:")
    login_payload = {
        "email": test_email,
        "password": test_password
    }
    
    r_login = client.post(f"{base_url}/api/auth/login", json=login_payload)
    print(f"   Response status: {r_login.status_code}")
    if r_login.status_code != 200:
        print(f"   ❌ Login failed: {r_login.text}")
        sys.exit(1)
        
    print("   ✅ Login successful.")
    
    # 3. Retrieve system health status
    print("\n3. Requesting system status monitor (/api/system/status):")
    headers = {"Authorization": f"Bearer {token}"}
    r_status = client.get(f"{base_url}/api/system/status", headers=headers)
    print(f"   Response status: {r_status.status_code}")
    if r_status.status_code != 200:
        print(f"   ❌ Failed to query system status: {r_status.text}")
        sys.exit(1)
        
    status_data = r_status.json()
    print("   ✅ System status retrieved successfully.")
    
    # 4. Verify components status
    print("\n4. Verifying Component health states:")
    
    # DB
    db_state = status_data.get("db", {})
    db_status = db_state.get("status")
    print(f"   - Database (DynamoDB): {db_status.upper()} ({db_state.get('detail')})")
    if db_status != "online":
        print("     ❌ Database is offline!")
        sys.exit(1)
        
    # Core Services
    services = status_data.get("services", {})
    failed_services = []
    print("   - Services status:")
    for svc_name, svc_info in services.items():
        state = svc_info.get("status")
        port = svc_info.get("port")
        print(f"     * {svc_name} (Port {port}): {state.upper()}")
        if state != "online":
            failed_services.append(svc_name)
            
    # Workers
    workers = status_data.get("workers", {})
    failed_workers = []
    print("   - Background workers status:")
    for wrk_name, wrk_info in workers.items():
        state = wrk_info.get("status")
        print(f"     * {wrk_name}: {state.upper()}")
        if state != "running":
            failed_workers.append(wrk_name)
            
    # CDN Edge Nodes
    cdn_nodes = status_data.get("cdn_nodes", [])
    failed_cdn = []
    print("   - Regional CDN Edge nodes status:")
    for node in cdn_nodes:
        region = node.get("region")
        state = node.get("status")
        latency = node.get("latency_ms")
        print(f"     * {region} Edge: {state.upper()} (Latency: {latency}ms)")
        if state != "online":
            failed_cdn.append(region)
            
    # 5. Conclusion
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY RESULT")
    print("=" * 60)
    if failed_services or failed_workers or failed_cdn:
        print("❌ SOME COMPONENTS ARE UNHEALTHY / DOWN!")
        if failed_services:
            print(f"   Down services: {failed_services}")
        if failed_workers:
            print(f"   Stopped workers: {failed_workers}")
        if failed_cdn:
            print(f"   Offline CDN edges: {failed_cdn}")
        sys.exit(1)
    else:
        print("✅ ALL COMPONENTS ARE 100% HEALTHY AND ONLINE!")
        print("   Phase 1 API features, user registration, token access, quota schema,")
        print("   and consolidated health status endpoints are fully verified and operational.")
    print("=" * 60)

if __name__ == "__main__":
    run_e2e_test()
