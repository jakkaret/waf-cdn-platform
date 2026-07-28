import asyncio
import struct
import json
import httpx
import sys
import os

# Frame types
MSG_AUTH = 1
MSG_AUTH_RESP = 2
MSG_CONNECT = 3
MSG_DATA = 4
MSG_CLOSE = 5

class WafTunnelAgent:
    def __init__(self, config_path="agent.conf"):
        self.config_path = config_path
        self.waf_token = None
        self.backend_url = None
        
        # Local target connection tracking
        self.connections = {}  # {conn_id: (reader, writer)}
        self.tasks = []

    def load_config(self):
        # 1. Check env first
        self.waf_token = os.getenv("WAF_TOKEN")
        self.backend_url = os.getenv("WAF_BACKEND_URL", "http://localhost:8000")
        
        # 2. Check agent.conf if env not found
        if not self.waf_token and os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == "WAF_TOKEN":
                                self.waf_token = v.strip().strip('"')
                            elif k.strip() == "WAF_BACKEND_URL":
                                self.backend_url = v.strip().strip('"')
            except Exception as e:
                print(f"[Agent] Error reading config file: {e}")
                
        if not self.waf_token:
            print("[Agent] ❌ Error: WAF_TOKEN is not set in environment or agent.conf!")
            sys.exit(1)
            
        print(f"[Agent] Loaded WAF_TOKEN: {self.waf_token[:10]}...")
        print(f"[Agent] Backend API URL: {self.backend_url}")

    async def verify_token(self):
        """Contact backend to verify WAF_TOKEN and fetch tunnel parameters."""
        print("[Agent] Contacting WAF backend to verify token...")
        async with httpx.AsyncClient() as client:
            try:
                r = await client.post(
                    f"{self.backend_url}/api/auth/tunnel/verify",
                    json={"waf_token": self.waf_token},
                    timeout=5.0
                )
            except Exception as e:
                print(f"[Agent] ❌ Failed to connect to backend: {e}")
                sys.exit(1)
                
        if r.status_code != 200:
            print(f"[Agent] ❌ Token validation failed: {r.text}")
            sys.exit(1)
            
        data = r.json()
        print(f"[Agent] ✅ Token authorized for origin: {data.get('label')}")
        return data

    async def send_frame(self, writer, msg_type, conn_id, payload=b""):
        header = struct.pack("!B16sI", msg_type, conn_id, len(payload))
        writer.write(header + payload)
        await writer.drain()

    async def read_frame(self, reader):
        header = await reader.readexactly(21)
        msg_type, conn_id, payload_len = struct.unpack("!B16sI", header)
        payload = await reader.readexactly(payload_len)
        return msg_type, conn_id, payload

    async def handle_target_data(self, conn_id, target_reader, tunnel_writer):
        """Reads data from the customer local web server and pipes it to WAF server."""
        try:
            while True:
                data = await target_reader.read(4096)
                if not data:
                    break
                await self.send_frame(tunnel_writer, MSG_DATA, conn_id, data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[Agent] Error reading from local target for {conn_id.hex()}: {e}")
        finally:
            try:
                await self.send_frame(tunnel_writer, MSG_CLOSE, conn_id)
            except Exception:
                pass

    async def start(self):
        self.load_config()
        config = await self.verify_token()
        
        server_host = config.get("tunnel_server_host")
        server_port = config.get("tunnel_server_port")
        target_host = config.get("local_target_host")
        target_port = config.get("local_target_port")
        
        # In case we run in Docker, handle localhost resolution
        if server_host == "localhost" and os.path.exists("/.dockerenv"):
            server_host = "host.docker.internal"
            
        print(f"[Agent] Connecting to WAF Tunnel Server at {server_host}:{server_port}...")
        try:
            tunnel_reader, tunnel_writer = await asyncio.open_connection(server_host, server_port)
        except Exception as e:
            print(f"[Agent] ❌ Failed to connect to WAF Tunnel Server: {e}")
            sys.exit(1)
            
        print("[Agent] Sending authentication frame...")
        # Send AUTH frame
        auth_payload = json.dumps({"waf_token": self.waf_token}).encode('utf-8')
        zero_id = b"\x00" * 16
        await self.send_frame(tunnel_writer, MSG_AUTH, zero_id, auth_payload)
        
        # Read AUTH_RESP
        msg_type, _, payload = await self.read_frame(tunnel_reader)
        if msg_type != MSG_AUTH_RESP:
            print("[Agent] ❌ Invalid handshake response. Closing.")
            tunnel_writer.close()
            return
            
        auth_resp = json.loads(payload.decode('utf-8'))
        if auth_resp.get("status") != "success":
            print("[Agent] ❌ Handshake authentication rejected by server.")
            tunnel_writer.close()
            return
            
        print(f"[Agent] 🚀 Secure mTLS-like Outbound Tunnel established! Remote WAF port: {auth_resp.get('remote_bind_port')}")
        print(f"[Agent] Forwarding traffic locally to {target_host}:{target_port}")
        
        # Stream loop
        try:
            while True:
                msg_type, conn_id, payload = await self.read_frame(tunnel_reader)
                
                if msg_type == MSG_CONNECT:
                    # Connect to local web origin server (e.g. Nginx/DVWA)
                    print(f"[Agent] Establishing connection to local web target {target_host}:{target_port}...")
                    try:
                        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
                        self.connections[conn_id] = (target_reader, target_writer)
                        
                        # Forward target responses back to WAF
                        t = asyncio.create_task(self.handle_target_data(conn_id, target_reader, tunnel_writer))
                        self.tasks.append(t)
                    except Exception as e:
                        print(f"[Agent] ❌ Failed to connect to local target: {e}")
                        await self.send_frame(tunnel_writer, MSG_CLOSE, conn_id)
                        
                elif msg_type == MSG_DATA:
                    if conn_id in self.connections:
                        _, target_writer = self.connections[conn_id]
                        target_writer.write(payload)
                        await target_writer.drain()
                        
                elif msg_type == MSG_CLOSE:
                    if conn_id in self.connections:
                        _, target_writer = self.connections[conn_id]
                        target_writer.close()
                        del self.connections[conn_id]
                        print(f"[Agent] Target connection {conn_id.hex()} closed by server.")
                        
        except Exception as e:
            print(f"[Agent] Connection to tunnel server lost: {e}")
        finally:
            tunnel_writer.close()
            for t in self.tasks:
                t.cancel()
            for _, (_, target_writer) in self.connections.items():
                target_writer.close()

if __name__ == "__main__":
    agent = WafTunnelAgent()
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        print("Agent stopped.")
