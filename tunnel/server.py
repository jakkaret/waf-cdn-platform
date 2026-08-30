"""CloudWAF private tunnel server.

Runs on the WAF node and exposes two listeners:

  * an agent listener (TLS) that customer agents dial out to and hold open;
  * a vhost listener (plaintext, loopback) that nginx proxies into.

nginx terminates TLS, runs ModSecurity, and then proxies the request here with
the original Host header intact. This process reads that header, finds the
agent that registered the hostname, and relays the connection over that
agent's existing outbound tunnel. A customer origin therefore never opens an
inbound port, and traffic still passes the full WAF chain first — routing by
hostname rather than by a per-origin port also means two origins listening on
the same local port do not collide.

Credentials are per-origin secrets verified against the dashboard API, so a
leaked agent token exposes one origin rather than the whole fleet.

Environment:
    TUNNEL_AGENT_HOST/PORT   agent listener bind (default 0.0.0.0:8050)
    TUNNEL_VHOST_HOST/PORT   nginx-facing listener (default 127.0.0.1:8060)
    TUNNEL_TLS_CERT/KEY      certificate presented to agents (required)
    TUNNEL_VERIFY_URL        dashboard endpoint that validates an agent token
    TUNNEL_STATE_FILE        where to write status for the dashboard to read
"""

import asyncio
import json
import logging
import os
import ssl
import time
import uuid
from typing import Dict, Optional, Tuple

import httpx

from protocol import (
    HEADER_LEN,
    MAX_PAYLOAD,
    MSG_AUTH,
    MSG_AUTH_RESP,
    MSG_CLOSE,
    MSG_CONNECT,
    MSG_DATA,
    MSG_PING,
    MSG_PONG,
    ProtocolError,
    ZERO_ID,
    parse_json,
    read_frame,
    send_frame,
    send_json,
)

AGENT_HOST = os.getenv("TUNNEL_AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.getenv("TUNNEL_AGENT_PORT", "8050"))
VHOST_HOST = os.getenv("TUNNEL_VHOST_HOST", "127.0.0.1")
VHOST_PORT = int(os.getenv("TUNNEL_VHOST_PORT", "8060"))
TLS_CERT = os.getenv("TUNNEL_TLS_CERT", "/etc/cloudwaf-tunnel/server.crt")
TLS_KEY = os.getenv("TUNNEL_TLS_KEY", "/etc/cloudwaf-tunnel/server.key")
VERIFY_URL = os.getenv("TUNNEL_VERIFY_URL", "http://127.0.0.1:8000/api/tunnel/verify-agent")
STATE_FILE = os.getenv("TUNNEL_STATE_FILE", "/var/lib/cloudwaf-tunnel/state.json")

AUTH_TIMEOUT = 10.0       # an agent must authenticate this soon after connecting
CONNECT_TIMEOUT = 10.0    # how long a browser waits for the agent to answer
IDLE_TIMEOUT = 90.0       # no frame from an agent for this long: drop it
HEAD_LIMIT = 32 * 1024    # cap on the request head we buffer to find Host

logging.basicConfig(level=os.getenv("TUNNEL_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tunnel-server")


class Agent:
    """One authenticated agent connection and the hostnames it serves."""

    def __init__(self, agent_id: str, origin_label: str, writer: asyncio.StreamWriter, domains: Dict[str, dict]):
        self.agent_id = agent_id
        self.origin_label = origin_label
        self.writer = writer
        self.domains = domains
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.bytes_in = 0
        self.bytes_out = 0
        self.requests = 0
        # conn_id -> writer back to the browser
        self.clients: Dict[bytes, asyncio.StreamWriter] = {}
        # conn_id -> future resolved once the agent confirms or refuses
        self.pending: Dict[bytes, asyncio.Future] = {}
        self._lock = asyncio.Lock()

    async def send(self, msg_type: int, conn_id: bytes, payload: bytes = b"") -> None:
        # One writer shared by every proxied connection, so serialise access:
        # interleaved frames would corrupt the stream.
        async with self._lock:
            await send_frame(self.writer, msg_type, conn_id, payload)

    def close(self) -> None:
        for writer in list(self.clients.values()):
            try:
                writer.close()
            except Exception:
                pass
        self.clients.clear()
        for fut in list(self.pending.values()):
            if not fut.done():
                fut.set_result(False)
        self.pending.clear()
        try:
            self.writer.close()
        except Exception:
            pass


class Registry:
    """Maps hostname -> Agent. Last successful registration wins."""

    def __init__(self):
        self.by_domain: Dict[str, Agent] = {}
        self.agents: Dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        for domain in agent.domains:
            existing = self.by_domain.get(domain)
            if existing is not None and existing is not agent:
                log.warning("domain %s reassigned from agent %s to %s",
                            domain, existing.agent_id, agent.agent_id)
            self.by_domain[domain] = agent
        self.agents[agent.agent_id] = agent

    def unregister(self, agent: Agent) -> None:
        for domain in agent.domains:
            if self.by_domain.get(domain) is agent:
                del self.by_domain[domain]
        self.agents.pop(agent.agent_id, None)

    def lookup(self, host: str) -> Optional[Agent]:
        return self.by_domain.get(host.lower())

    def snapshot(self) -> dict:
        now = time.time()
        return {
            "updated_at": now,
            "agent_count": len(self.agents),
            "domain_count": len(self.by_domain),
            "agents": [
                {
                    "agent_id": a.agent_id,
                    "origin_label": a.origin_label,
                    "domains": sorted(a.domains),
                    "uptime_seconds": round(now - a.connected_at, 1),
                    "last_seen_seconds_ago": round(now - a.last_seen, 1),
                    "active_connections": len(a.clients),
                    "requests": a.requests,
                    "bytes_in": a.bytes_in,
                    "bytes_out": a.bytes_out,
                }
                for a in self.agents.values()
            ],
        }


registry = Registry()


def write_state() -> None:
    """Publish status so the dashboard can report real tunnel health."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = f"{STATE_FILE}.tmp"
        with open(tmp, "w") as fh:
            json.dump(registry.snapshot(), fh)
        os.replace(tmp, STATE_FILE)
    except Exception as exc:
        log.debug("could not write state file: %s", exc)


async def verify_agent_token(token: str, domains) -> Optional[dict]:
    """Ask the dashboard whether this token may serve these hostnames.

    Returning None denies the connection. Any transport failure also denies:
    an unreachable verifier must not become an open door.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(VERIFY_URL, json={"token": token, "domains": domains})
    except Exception as exc:
        log.error("verifier unreachable, denying agent: %s", exc)
        return None
    if resp.status_code != 200:
        log.warning("verifier rejected an agent: HTTP %s", resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        log.error("verifier returned a non-JSON body")
        return None


# --------------------------------------------------------------------------
# Agent side
# --------------------------------------------------------------------------

async def handle_agent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    agent: Optional[Agent] = None
    try:
        try:
            msg_type, _, payload = await asyncio.wait_for(read_frame(reader), AUTH_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("agent from %s never authenticated", peer)
            return
        if msg_type != MSG_AUTH:
            log.warning("agent from %s sent %s before authenticating", peer, msg_type)
            return

        auth = parse_json(payload)
        token = auth.get("token") or ""
        routes = auth.get("routes") or {}
        if not token or not isinstance(routes, dict) or not routes:
            await send_json(writer, MSG_AUTH_RESP, ZERO_ID,
                            {"status": "rejected", "reason": "token and routes are required"})
            return

        domains = [str(d).lower() for d in routes.keys()]
        verdict = await verify_agent_token(token, domains)
        if not verdict:
            await send_json(writer, MSG_AUTH_RESP, ZERO_ID,
                            {"status": "rejected", "reason": "token not accepted for these domains"})
            return

        allowed = {str(d).lower() for d in verdict.get("allowed_domains", domains)}
        accepted = {d: routes[k] for k, d in ((k, str(k).lower()) for k in routes) if d in allowed}
        if not accepted:
            await send_json(writer, MSG_AUTH_RESP, ZERO_ID,
                            {"status": "rejected", "reason": "no requested domain is allowed for this token"})
            return

        agent = Agent(
            agent_id=verdict.get("origin_id") or uuid.uuid4().hex,
            origin_label=verdict.get("label") or "unknown",
            writer=writer,
            domains=accepted,
        )
        registry.register(agent)
        write_state()
        # Never log the token itself, only what it unlocked.
        log.info("agent %s (%s) authenticated from %s serving %s",
                 agent.agent_id, agent.origin_label, peer, sorted(accepted))
        await send_json(writer, MSG_AUTH_RESP, ZERO_ID,
                        {"status": "accepted", "domains": sorted(accepted), "keepalive_seconds": 30})

        while True:
            try:
                msg_type, conn_id, payload = await asyncio.wait_for(read_frame(reader), IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                log.info("agent %s idle past %.0fs, closing", agent.agent_id, IDLE_TIMEOUT)
                break
            agent.last_seen = time.time()

            if msg_type == MSG_DATA:
                client = agent.clients.get(conn_id)
                if client is not None and not client.is_closing():
                    agent.bytes_in += len(payload)
                    client.write(payload)
                    await client.drain()
            elif msg_type == MSG_CONNECT:
                # Agent's answer to our CONNECT: did the local target accept?
                fut = agent.pending.pop(conn_id, None)
                ok = bool(parse_json(payload).get("ok")) if payload else False
                if fut is not None and not fut.done():
                    fut.set_result(ok)
            elif msg_type == MSG_CLOSE:
                fut = agent.pending.pop(conn_id, None)
                if fut is not None and not fut.done():
                    fut.set_result(False)
                client = agent.clients.pop(conn_id, None)
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
            elif msg_type == MSG_PING:
                await agent.send(MSG_PONG, ZERO_ID)
            else:
                log.debug("agent %s sent unknown frame %s", agent.agent_id, msg_type)

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except ProtocolError as exc:
        log.warning("protocol error from %s: %s", peer, exc)
    except Exception as exc:
        log.exception("agent session from %s failed: %s", peer, exc)
    finally:
        if agent is not None:
            registry.unregister(agent)
            agent.close()
            write_state()
            log.info("agent %s disconnected", agent.agent_id)
        else:
            try:
                writer.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# nginx side
# --------------------------------------------------------------------------

def _extract_host(head: bytes) -> Optional[str]:
    for line in head.split(b"\r\n")[1:]:
        if not line:
            break
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("latin-1")
            return host.split(":")[0].lower()
    return None


async def _read_head(reader: asyncio.StreamReader) -> Tuple[bytes, Optional[str]]:
    """Buffer just enough of the request to read its Host header."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > HEAD_LIMIT:
            return buf, None
        chunk = await reader.read(4096)
        if not chunk:
            break
        buf += chunk
    return buf, _extract_host(buf)


async def _reply(writer: asyncio.StreamWriter, status: str, body: str) -> None:
    payload = body.encode("utf-8")
    writer.write(
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n".encode("latin-1") + payload
    )
    try:
        await writer.drain()
    except Exception:
        pass


async def handle_vhost(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    conn_id = uuid.uuid4().bytes
    agent: Optional[Agent] = None
    try:
        head, host = await asyncio.wait_for(_read_head(reader), 15.0)
        if not head:
            return
        if not host:
            await _reply(writer, "400 Bad Request", "No Host header.\n")
            return

        agent = registry.lookup(host)
        if agent is None:
            await _reply(writer, "502 Bad Gateway", f"No tunnel agent is connected for {host}.\n")
            return

        route = agent.domains.get(host, {})
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        agent.pending[conn_id] = fut
        await agent.send(MSG_CONNECT, conn_id,
                         json.dumps({"domain": host, "target": route}).encode("utf-8"))
        try:
            ok = await asyncio.wait_for(fut, CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            agent.pending.pop(conn_id, None)
            await _reply(writer, "504 Gateway Timeout", f"Agent for {host} did not answer.\n")
            return
        if not ok:
            await _reply(writer, "502 Bad Gateway", f"Agent for {host} could not reach its local target.\n")
            return

        agent.clients[conn_id] = writer
        agent.requests += 1
        agent.bytes_out += len(head)
        await agent.send(MSG_DATA, conn_id, head)

        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            agent.bytes_out += len(chunk)
            await agent.send(MSG_DATA, conn_id, chunk)

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        log.debug("vhost connection %s ended: %s", conn_id.hex()[:8], exc)
    finally:
        if agent is not None:
            agent.clients.pop(conn_id, None)
            agent.pending.pop(conn_id, None)
            try:
                await agent.send(MSG_CLOSE, conn_id)
            except Exception:
                pass
        try:
            writer.close()
        except Exception:
            pass


async def state_writer() -> None:
    while True:
        await asyncio.sleep(10)
        write_state()


def build_ssl_context() -> ssl.SSLContext:
    if not os.path.exists(TLS_CERT) or not os.path.exists(TLS_KEY):
        raise SystemExit(
            f"TLS material missing ({TLS_CERT}, {TLS_KEY}). The agent token crosses this "
            "connection, so the server refuses to start without TLS."
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    return ctx


async def main() -> None:
    ctx = build_ssl_context()
    agent_server = await asyncio.start_server(handle_agent, AGENT_HOST, AGENT_PORT, ssl=ctx)
    vhost_server = await asyncio.start_server(handle_vhost, VHOST_HOST, VHOST_PORT)
    log.info("agent listener on %s:%s (TLS)", AGENT_HOST, AGENT_PORT)
    log.info("vhost listener on %s:%s", VHOST_HOST, VHOST_PORT)
    write_state()
    asyncio.create_task(state_writer())
    async with agent_server, vhost_server:
        await asyncio.gather(agent_server.serve_forever(), vhost_server.serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("shutting down")
