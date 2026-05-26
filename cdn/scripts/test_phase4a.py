import requests
import time

# Central Log
def generate_logs():
    print("=== Generating test requests to CDN edge nodes ===")
    edges = {"SG": 8081, "JP": 8082, "TH": 8086}
    
    for region, port in edges.items():
        print(f"Sending requests to {region} edge (Port {port})...")
        try:
            # Dynamic request
            r1 = requests.get(f"http://localhost:{port}/", timeout=2)
            print(f"  -> Dynamic GET / : {r1.status_code} | Cache: {r1.headers.get('X-Cache-Status', 'MISS')}")
            
            # Static request
            r2 = requests.get(f"http://localhost:{port}/test-static.css", timeout=2)
            print(f"  -> Static GET /test-static.css : {r2.status_code} | Cache: {r2.headers.get('X-Cache-Status', 'MISS')}")
        except Exception as e:
            print(f"  -> Error connecting to {region} edge: {e}")

if __name__ == "__main__":
    generate_logs()
    print("\nLogs should now be written to logs/cdn/<region>/access.json.")
    print("The backend cdn_log_forward_worker should pick them up automatically and save to DynamoDB.")
    print("To verify, log in to the Dashboard and use the API: GET /api/cdn/logs?region=ALL")
