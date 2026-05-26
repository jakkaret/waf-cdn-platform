import urllib3
import requests

# Disable InsecureRequestWarning for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTPS_EDGES = {
    "SG": "https://localhost:8441",
    "JP": "https://localhost:8442",
    "TH": "https://localhost:8446",
}

def test_tls(region, base_url):
    print(f"\n--- Testing TLS/HTTPS for {region} ({base_url}) ---")
    url = f"{base_url}/healthz"
    try:
        # Use verify=False because the certificates are self-signed
        resp = requests.get(url, verify=False, timeout=5)
        print(f"Status Code : {resp.status_code}")
        print(f"Response    : {resp.text.strip()}")
        
        if resp.status_code == 200:
            print("✅ SUCCESS: HTTPS endpoint is reachable and returning data.")
        else:
            print(f"❌ WARNING: Reached HTTPS endpoint but got unexpected status {resp.status_code}.")
            
    except requests.exceptions.SSLError as e:
        print(f"❌ FAILED: SSL Error occurred. This means the TLS connection failed. Details: {e}")
    except requests.exceptions.ConnectionError:
        print("❌ FAILED: Connection Error. Is the container running and port exposed?")
    except Exception as e:
        print(f"❌ FAILED: Unexpected error: {e}")

if __name__ == "__main__":
    for region, url in HTTPS_EDGES.items():
        test_tls(region, url)
