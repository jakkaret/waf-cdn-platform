import time
import httpx
import sys

WAF_HTTP_URL = "http://localhost:8080" # Calling Nginx WAF HTTP port directly

def main():
    print("=" * 60)
    print("🚀 RUNNING E2E TEST FOR DISTRIBUTED RATE LIMITER (REDIS + LUA)")
    print("=" * 60)
    
    client = httpx.Client(timeout=3.0)
    
    # Clear rate limit keys in Redis to ensure clean test state
    print("[Test] Clearing Redis rate limit logs...")
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379)
        keys = r.keys("rate:limit:*")
        if keys:
            r.delete(*keys)
        print("[Test] Redis rate limits cleared.")
    except Exception as e:
        print(f"[Test] Warning: Failed to connect to Redis directly to clear keys: {e}")
        
    print("\n--- Sending 10 allowed requests (Limit: 10 requests per 10 seconds) ---")
    allowed_count = 0
    
    for i in range(1, 11):
        try:
            # We call /healthz which is not rate-limited, wait!
            # Our Nginx default.conf.template has location = /healthz separate from location /
            # And location / is the one with auth_request rate limiting!
            # So we should call "/" (home page) or another path to trigger the rate limiter!
            r = client.get(f"{WAF_HTTP_URL}/")
            print(f"Request #{i}: Status {r.status_code}")
            
            # Since Nginx proxy_pass to dvwa, it might return 200 or 302, but NOT 429
            if r.status_code != 429:
                allowed_count += 1
            else:
                print("❌ Unexpectedly rate limited early!")
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            sys.exit(1)
            
    print(f"Allowed requests count: {allowed_count}/10")
    assert allowed_count == 10, "Should have allowed exactly 10 requests"
    
    print("\n--- Sending the 11th request (Expects 429 Too Many Requests) ---")
    try:
        r = client.get(f"{WAF_HTTP_URL}/")
        print(f"Request #11: Status {r.status_code}")
        print(f"Response headers: {dict(r.headers)}")
        print(f"Response body: {r.text}")
        
        # Verify 429 status code
        assert r.status_code == 429, "11th request should have been blocked with 429"
        
        # Verify Retry-After header
        retry_after = r.headers.get("retry-after")
        print(f"✅ Received Retry-After: {retry_after} seconds")
        assert retry_after is not None, "Response must include Retry-After header"
        wait_seconds = int(retry_after)
        
        print(f"\n--- Waiting for {wait_seconds} seconds to let rate limit window slide ---")
        time.sleep(wait_seconds + 1)
        
        print("\n--- Requesting again after wait (Expects 200/302 success) ---")
        r = client.get(f"{WAF_HTTP_URL}/")
        print(f"Post-wait Request: Status {r.status_code}")
        assert r.status_code != 429, "Request should be allowed after rate limit window reset"
        
        print("\n" + "=" * 60)
        print("✅ REDIS LUA SLIDING WINDOW RATE LIMITER TEST SUCCESSFUL!")
        print("   Nginx intercept checks with FastAPI backend, Redis evaluates Lua script,")
        print("   blocks excessive requests, and correctly sets the Retry-After header!")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
