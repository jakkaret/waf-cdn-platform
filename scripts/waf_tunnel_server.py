import asyncio
import struct
import json
import httpx
import sys

TUNNEL_PORT = 8050
API_VERIFY_URL = "http://localhost:8000/api/auth/tunnel/verify"

# Active tunnels registry: {tunnel_id: (reader, writer, remote_server_task, client_sockets)}
# client_sockets: {conn_id: (reader, writer)}
active_tunnels = {}

# Frame types
MSG_AUTH = 1
MSG_AUTH_RESP = 2
MSG_CONNECT = 3
MSG_DATA = 4
MSG_CLOSE = 5

async def send_frame(writer, msg_type, conn_id, payload=b""):
    # Header format: msg_type (1 byte) + conn_id (16 bytes) + payload_len (4 bytes)
    header = struct.pack("!B16sI", msg_type, conn_id, len(payload))
    writer.write(header + payload)
    await writer.drain()

async def read_frame(reader):
    header = await reader.readexactly(21)
    msg_type, conn_id, payload_len = struct.unpack("!B16sI", header)
    payload = await reader.readexactly(payload_len)
    return msg_type, conn_id, payload

async def handle_client_data(conn_id, client_reader, tunnel_writer):
    """Read data from web client and forward it through the tunnel."""
    try:
        while True:
            data = await client_reader.read(4096)
            if not data:
                break
            await send_frame(tunnel_writer, MSG_DATA, conn_id, data)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"[Tunnel Server] Error reading client data for {conn_id.hex()}: {e}")
    finally:
        try:
            await send_frame(tunnel_writer, MSG_CLOSE, conn_id)
        except Exception:
            pass

async def start_remote_listener(bind_port, tunnel_writer, tunnel_id):
    """Listens on WAF side port for incoming client connections."""
    client_sockets = {}
    active_tunnels[tunnel_id]["client_sockets"] = client_sockets

    async def on_client_connect(client_reader, client_writer):
        conn_id = uuid_bytes = struct.pack("!16s", bytes.fromhex(sys.modules['uuid'].uuid4().hex))
        client_sockets[conn_id] = (client_reader, client_writer)
        print(f"[Tunnel Server] New client connection on port {bind_port}, tunnel_id={conn_id.hex()}")
        
        # Notify agent to connect to local target
        await send_frame(tunnel_writer, MSG_CONNECT, conn_id)
        
        # Start reading client data
        task = asyncio.create_task(handle_client_data(conn_id, client_reader, tunnel_writer))
        active_tunnels[tunnel_id]["tasks"].append(task)

    server = await asyncio.start_server(on_client_connect, "0.0.0.0", bind_port)
    print(f"[Tunnel Server] Bound and listening on WAF side port {bind_port}")
    return server

async def handle_tunnel_connection(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"[Tunnel Server] Incoming tunnel connection from {peer}")
    tunnel_id = None
    remote_server = None
    
    try:
        # 1. Read authentication frame
        msg_type, conn_id, payload = await read_frame(reader)
        if msg_type != MSG_AUTH:
            print("[Tunnel Server] Initial packet was not AUTH. Closing.")
            writer.close()
            return
            
        auth_data = json.loads(payload.decode('utf-8'))
        waf_token = auth_data.get("waf_token")
        
        # 2. Verify token with Backend API
        print(f"[Tunnel Server] Verifying token: {waf_token[:10]}...")
        async with httpx.AsyncClient() as client:
            resp = await client.post(API_VERIFY_URL, json={"waf_token": waf_token})
            
        if resp.status_code != 200:
            print(f"[Tunnel Server] Authorization failed: {resp.text}")
            await send_frame(writer, MSG_AUTH_RESP, conn_id, json.dumps({"status": "failed"}).encode('utf-8'))
            writer.close()
            return
            
        verify_data = resp.json()
        print(f"[Tunnel Server] Token authorized for origin: {verify_data.get('label')}")
        
        import hashlib
        tunnel_id = hashlib.md5(verify_data.get("origin_id").encode('utf-8')).digest()
        bind_port = verify_data.get("remote_bind_port")
        
        # 3. Respond with SUCCESS
        await send_frame(writer, MSG_AUTH_RESP, conn_id, json.dumps({
            "status": "success",
            "remote_bind_port": bind_port
        }).encode('utf-8'))
        
        # 4. Start local listener for this tunnel on the remote bind port
        active_tunnels[tunnel_id] = {
            "reader": reader,
            "writer": writer,
            "tasks": [],
            "client_sockets": {}
        }
        
        remote_server = await start_remote_listener(bind_port, writer, tunnel_id)
        
        # Import uuid for conn_id generation
        import uuid
        sys.modules['uuid'] = uuid
        
        # 5. Continuous tunnel loop
        while True:
            msg_type, conn_id, payload = await read_frame(reader)
            client_sockets = active_tunnels[tunnel_id]["client_sockets"]
            
            if msg_type == MSG_DATA:
                if conn_id in client_sockets:
                    _, client_writer = client_sockets[conn_id]
                    client_writer.write(payload)
                    await client_writer.drain()
            elif msg_type == MSG_CLOSE:
                if conn_id in client_sockets:
                    _, client_writer = client_sockets[conn_id]
                    client_writer.close()
                    del client_sockets[conn_id]
                    print(f"[Tunnel Server] Connection {conn_id.hex()} closed by agent.")
                    
    except Exception as e:
        print(f"[Tunnel Server] Tunnel session ended for {peer}: {e}")
    finally:
        writer.close()
        if remote_server:
            remote_server.close()
            await remote_server.wait_closed()
        if tunnel_id in active_tunnels:
            for task in active_tunnels[tunnel_id]["tasks"]:
                task.cancel()
            for _, (_, client_writer) in active_tunnels[tunnel_id]["client_sockets"].items():
                client_writer.close()
            del active_tunnels[tunnel_id]
            print(f"[Tunnel Server] Cleaned up tunnel: {tunnel_id.hex() if tunnel_id else 'unknown'}")

async def main():
    server = await asyncio.start_server(handle_tunnel_connection, "0.0.0.0", TUNNEL_PORT)
    print(f"[Tunnel Server] Secure WAF Tunnel Server listening on port {TUNNEL_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped.")
