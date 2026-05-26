import requests
import time
import socket

def test_status_endpoint():
    print("=== Testing GeoDNS /status Endpoint ===")
    try:
        response = requests.get("http://localhost:8053/status", timeout=5)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"Node Status: {response.json()}")
        else:
            print("Failed to get valid status.")
    except Exception as e:
        print(f"Error calling /status: {e}")
    print()

def test_dns_resolution(domain="cdn.local", server="127.0.0.1", port=5533):
    print(f"=== Testing DNS Resolution for {domain} on {server}:{port} ===")
    try:
        # Note: basic socket test for DNS resolution
        # dnslib would be better, but we only rely on built-in socket/requests for testing
        print("Note: To properly test GeoDNS failover routing dynamically, you need to simulate different client IPs.")
        print("If you run 'dig @127.0.0.1 -p 5533 cdn.local' you should get an A record.")
        
        # Simple test to see if GeoDNS resolves anything locally (it will use localhost IP 127.0.0.1 which falls back to TH)
        import subprocess
        result = subprocess.run(["nslookup", "-port=5533", domain, server], capture_output=True, text=True)
        if result.returncode == 0:
            print("DNS Resolution Output:")
            print(result.stdout)
        else:
            print("nslookup command failed or not found. Please try with 'dig @127.0.0.1 -p 5533 cdn.local' manually.")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error during DNS test: {e}")

if __name__ == "__main__":
    print("Starting Phase 3B Test Script (Failover & Status)\n")
    test_status_endpoint()
    test_dns_resolution()
    print("\nTest completed.")
