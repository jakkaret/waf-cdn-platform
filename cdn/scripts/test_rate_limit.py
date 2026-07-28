import sys
import time
from concurrent.futures import ThreadPoolExecutor
import requests

EDGES = {
    "SG": "http://localhost:8081",
    "JP": "http://localhost:8082",
    "TH": "http://localhost:8086",
}

def hit_edge(url):
    try:
        resp = requests.get(url, timeout=2)
        return resp.status_code, resp.headers.get("X-RateLimit-Limit")
    except requests.exceptions.ConnectionError:
        return 0, "Connection Error (Container might be down or port mapping incorrect)"
    except Exception as e:
        return 0, str(e)

def test_rate_limit(region, base_url) -> bool:
    print(f"\n--- Testing Rate Limit for {region} ({base_url}) ---")
    url = f"{base_url}/"
    success_count = 0
    too_many_req_count = 0
    limit_header = None
    
    # Send 150 requests quickly to exhaust the burst limit (SG/JP burst=60, TH burst=100)
    num_requests = 150
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(hit_edge, [url] * num_requests))
        
    for status, header in results:
        # Accept 200, 403, 404, 502, etc. as "passed rate limit check" because ModSecurity/Origin might return them
        if status not in [0, 429]: 
            success_count += 1
        elif status == 429:
            too_many_req_count += 1
        
        if header and not limit_header:
            limit_header = header

    print(f"Total Requests Sent : {num_requests}")
    print(f"Passed Requests     : {success_count}")
    print(f"Blocked (429)       : {too_many_req_count}")
    print(f"X-RateLimit-Limit   : {limit_header}")
    
    if too_many_req_count > 0:
        print("✅ SUCCESS: Rate Limiting is active and successfully blocked requests.")
        return True
    else:
        print("❌ FAILED: Did not encounter any 429 Too Many Requests responses. Rate limit might be inactive or burst is too high.")
        return False

if __name__ == "__main__":
    import sys
    overall_success = True
    for region, url in EDGES.items():
        if not test_rate_limit(region, url):
            overall_success = False
        time.sleep(1) # cool down before next region
        
    if not overall_success:
        print("\n❌ FAILED: One or more rate limit checks failed.")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: All rate limit checks passed.")
        sys.exit(0)
