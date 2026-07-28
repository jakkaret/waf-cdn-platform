import subprocess
import time
import httpx
import sys
import os
import signal
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

TEST_TOKEN = "test-tunnel-token-abc123xyz"

# 1. Simple Mock Customer Origin Server
class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello from tunneled customer origin!")
    def log_message(self, format, *args):
        pass # Suppress logging

def run_mock_origin(port=9001):
    httpd = HTTPServer(("localhost", port), MockHTTPHandler)
    print(f"[Mock Origin] Listening on port {port}")
    httpd.serve_forever()

def main():
    processes = []
    
    # 2. Add Test Origin to DynamoDB
    print("[Test] Inserting test origin into DynamoDB...")
    try:
        import dotenv; dotenv.load_dotenv()
        import boto3
        db = boto3.resource('dynamodb', region_name='ap-southeast-1')
        t = db.Table('waf_origins')
        t.put_item(Item={
            "id": TEST_TOKEN,
            "admin_user_id": "3755f84a-3941-4f22-a9e9-bdb0c7f5436b",
            "label": "E2E Tunnel Test Web",
            "ip": "127.0.0.1",
            "port": 9001,
            "status": "active"
        })
        print("[Test] Test origin inserted.")
    except Exception as e:
        print(f"[Test] Failed to insert origin in DB: {e}")
        sys.exit(1)
        
    try:
        # 3. Start Mock Origin Server in a thread
        origin_thread = threading.Thread(target=run_mock_origin, daemon=True)
        origin_thread.start()
        
        # 4. Start WAF Tunnel Server
        print("[Test] Launching WAF Tunnel Server...")
        server_proc = subprocess.Popen(
            [sys.executable, "-u", "scripts/waf_tunnel_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(("Tunnel Server", server_proc))
        time.sleep(2) # Wait for server to bind port 8050
        
        # 5. Create temporary config for agent
        print("[Test] Creating temporary agent config...")
        conf_path = "scripts/agent_test.conf"
        with open(conf_path, "w") as f:
            f.write(f'WAF_TOKEN="{TEST_TOKEN}"\n')
            f.write('WAF_BACKEND_URL="http://localhost:8000"\n')
            
        # 6. Start WAF Tunnel Agent
        print("[Test] Launching WAF Tunnel Agent...")
        agent_proc = subprocess.Popen(
            [sys.executable, "-u", "scripts/waf_tunnel_agent.py"],
            env={**os.environ, "WAF_TOKEN": TEST_TOKEN},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(("Tunnel Agent", agent_proc))
        
        # Wait for tunnel to establish
        print("[Test] Waiting for tunnel connection (5 seconds)...")
        time.sleep(5)
        
        # 7. Test connection through WAF bind port (19001)
        print("[Test] Sending HTTP request to WAF side remote port (19001)...")
        try:
            r = httpx.get("http://localhost:19001", timeout=3.0)
            print(f"[Test] Response code: {r.status_code}")
            print(f"[Test] Response body: {r.text}")
            
            if r.status_code == 200 and "Hello from tunneled customer origin!" in r.text:
                print("\n" + "=" * 60)
                print("✅ ZERO-TRUST TUNNEL INTEGRATION TEST SUCCESSFUL!")
                print("   The client agent wrapper validated the token, established a tunnel,")
                # Clean up test DB entry
                t.delete_item(Key={"id": TEST_TOKEN})
                print("   and proxied traffic safely without inbound firewall rules.")
                print("=" * 60)
                sys.exit(0)
            else:
                print("❌ Response content was incorrect.")
                sys.exit(1)
        except Exception as e:
            print(f"❌ Failed to reach tunneled port: {e}")
            sys.exit(1)
            
    finally:
        # Clean up processes
        print("\n[Test] Cleaning up processes...")
        # Clean up config
        if os.path.exists("scripts/agent_test.conf"):
            os.remove("scripts/agent_test.conf")
        # Kill server and agent
        for name, proc in processes:
            print(f"[Test] Stopping {name}...")
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=2)
                print(f"--- {name} STDOUT ---")
                print(stdout)
                print(f"--- {name} STDERR ---")
                print(stderr)
            except Exception as e:
                proc.kill()
                print(f"--- {name} failed to terminate cleanly: {e} ---")
        print("[Test] Done.")

if __name__ == "__main__":
    main()
