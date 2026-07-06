import httpx
import uuid

BASE_URL = "http://localhost:8000"

def test_auth():
    print("Testing auth endpoints...")
    test_email = f"test_{uuid.uuid4()}@example.com"
    test_pwd = "Password123!"
    
    with httpx.Client(base_url=BASE_URL) as client:
        # Register
        res = client.post("/api/auth/register", json={
            "email": test_email,
            "username": "testuser",
            "password": test_pwd,
            "role": "viewer"
        })
        print("Register:", res.status_code, res.text)
        assert res.status_code == 200, "Register failed"
        
        # Login
        res = client.post("/api/auth/login", json={
            "email": test_email,
            "password": test_pwd
        })
        print("Login:", res.status_code)
        assert res.status_code == 200, "Login failed"
        token = res.json().get("access_token")
        
        return token

def test_system_info(token):
    print("Testing protected endpoint (system info)...")
    with httpx.Client(base_url=BASE_URL) as client:
        res = client.get("/api/system/info", headers={"Authorization": f"Bearer {token}"})
        print("System Info:", res.status_code, res.text)
        assert res.status_code == 200, "System info failed"

def test_rate_limit():
    print("Testing rate limits on /api/auth/login...")
    with httpx.Client(base_url=BASE_URL) as client:
        # slowapi limit is 5/minute
        for i in range(6):
            res = client.post("/api/auth/login", json={
                "email": "dummy@example.com",
                "password": "wrong"
            })
            print(f"Request {i+1}: Status {res.status_code}")
            if res.status_code == 429:
                print("Rate limit working!")
                return
        assert False, "Rate limit not enforced"

if __name__ == "__main__":
    try:
        print("--- Starting System Integration Test ---")
        token = test_auth()
        test_system_info(token)
        test_rate_limit()
        print("✅ Integration tests passed successfully")
    except Exception as e:
        print(f"❌ Test failed: {e}")
