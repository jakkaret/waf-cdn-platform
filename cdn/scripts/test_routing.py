import requests

HTTP_EDGES = {
    "SG": "http://localhost:8081",
    "JP": "http://localhost:8082",
    "TH": "http://localhost:8086",
}

def test_routing(region, base_url) -> bool:
    print(f"\n--- Testing Routing for {region} ({base_url}) ---")
    success = True
    
    # 1. Dynamic Route
    dynamic_url = f"{base_url}/"
    limit_dyn = "N/A"
    print(f"[Dynamic Content Test] -> GET {dynamic_url}")
    try:
        resp_dyn = requests.get(dynamic_url, timeout=3)
        cc_dyn = resp_dyn.headers.get("Cache-Control", "N/A")
        limit_dyn = resp_dyn.headers.get("X-RateLimit-Limit", "N/A")
        
        print(f"  Cache-Control     : {cc_dyn}")
        print(f"  X-RateLimit-Limit : {limit_dyn}")
        
        if "max-age=600" in cc_dyn:
            print("  ✅ SUCCESS: Dynamic content cache policy (10 min) applied.")
        else:
            print("  ❌ FAILED: Dynamic content cache policy missing or incorrect.")
            success = False
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        success = False

    # 2. Static Route
    # Use a dummy static file to hit the static location block
    static_url = f"{base_url}/test-asset.css"
    print(f"\n[Static Asset Test] -> GET {static_url}")
    try:
        resp_stat = requests.get(static_url, timeout=3)
        cc_stat = resp_stat.headers.get("Cache-Control", "N/A")
        limit_stat = resp_stat.headers.get("X-RateLimit-Limit", "N/A")
        ct_options = resp_stat.headers.get("X-Content-Type-Options", "N/A")
        
        print(f"  Cache-Control          : {cc_stat}")
        print(f"  X-RateLimit-Limit      : {limit_stat}")
        print(f"  X-Content-Type-Options : {ct_options}")
        
        stat_pass = True
        if "max-age=3600" not in cc_stat or "immutable" not in cc_stat:
            print("  ❌ FAILED: Static asset cache policy (1 hour + immutable) missing or incorrect.")
            stat_pass = False
            success = False
        
        if ct_options != "nosniff":
            print("  ❌ FAILED: X-Content-Type-Options: nosniff is missing.")
            stat_pass = False
            success = False
            
        if limit_stat != limit_dyn and limit_stat != "N/A":
            print("  ✅ SUCCESS: Rate Limit for static assets is distinct from dynamic content.")
        else:
            print("  ❌ WARNING: Static asset rate limit is the same as dynamic or missing.")
            
        if stat_pass:
            print("  ✅ SUCCESS: Static routing headers applied correctly.")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        success = False

    return success

if __name__ == "__main__":
    import sys
    overall_success = True
    for region, url in HTTP_EDGES.items():
        if not test_routing(region, url):
            overall_success = False
            
    if not overall_success:
        print("\n❌ FAILED: One or more routing checks failed.")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: All routing checks passed.")
        sys.exit(0)
