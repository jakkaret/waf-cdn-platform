"""CloudWAF private tunnel agent.

Runs next to a customer's web server, which may sit entirely behind NAT or a
corporate firewall. The agent dials *out* to the WAF over TLS and holds that
connection open; the WAF pushes proxied requests down it. Nothing listens for
inbound connections on the customer side, so no port forwarding and no public
IP are required.

Config file (INI-style key=value, '#' comments), default /etc/cloudwaf-agent/agent.conf:

    SERVER_HOST=main.waf-it-kku.online
    SERVER_PORT=8050
    TOKEN=<per-origin secret issued by the dashboard>
    # Optional: pin the server certificate by SHA-256 fingerprint. Required
    # unless CA verification is enabled, so a self-signed WAF cert is still
    # authenticated and the token cannot be handed to an impostor.
    SERVER_FINGERPRINT=aa:bb:...
    # One ROUTE per hostname: ROUTE=<public hostname>=<local host>:<local port>
    ROUTE=vampi.waf-it-kku.online=127.0.0.1:5000

Any setting may also come from the environment (CLOUDWAF_TOKEN, etc.).
"""

import asyncio
import binascii
import hashlib
import json
import logging
import os
import ssl
import sys
from typing import Dict, Optional

from protocol import (
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

CONFIG_PATH = os.getenv("CLOUDWAF_AGENT_CONFIG", "/etc/cloudwaf-agent/agent.conf")

logging.basicConfig(level=os.getenv("CLOUDWAF_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tunnel-agent")

KEEPALIVE_SECONDS = 30
BACKOFF_START = 2.0
BACKOFF_MAX = 60.0


class Config:
    def __init__(self):
        self.server_host = ""
        self.server_port = 8050
        self.token = ""
        self.fingerprint = ""
        self.verify_ca = False
        self.routes: Dict[str, Dict[str, object]] = {}

    @classmethod
    def load(cls, path: str) -> "Config":
        cfg = cls()
        raw: Dict[str, list] = {}
        if os.path.exists(path):
            with open(path, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    raw.setdefault(key.strip().upper(), []).append(value.strip().strip('"'))

        def first(key: str, env: str, default: str = "") -> str:
            return os.getenv(env) or (raw.get(key, [""])[0]) or default

        cfg.server_host = first("SERVER_HOST", "CLOUDWAF_SERVER_HOST")
        cfg.server_port = int(first("SERVER_PORT", "CLOUDWAF_SERVER_PORT", "8050"))
        cfg.token = first("TOKEN", "CLOUDWAF_TOKEN")
        cfg.fingerprint = first("SERVER_FINGERPRINT", "CLOUDWAF_SERVER_FINGERPRINT").replace(":", "").lower()
        cfg.verify_ca = first("VERIFY_CA", "CLOUDWAF_VERIFY_CA", "false").lower() in ("1", "true", "yes")

        for entry in raw.get("ROUTE", []) + [r for r in os.getenv("CLOUDWAF_ROUTES", "").split(",") if r]:
            if "=" not in entry:
                continue
            domain, target = entry.split("=", 1)
            host, _, port = target.rpartition(":")
            if not host or not port.isdigit():
                log.warning("ignoring malformed ROUTE %r", entry)
                continue
            cfg.routes[domain.strip().lower()] = {"host": host.strip(), "port": int(port)}

        missing = [name for name, value in
                   (("SERVER_HOST", cfg.server_host), ("TOKEN", cfg.token)) if not value]
        if missing:
            raise SystemExit(f"agent config incomplete: {', '.join(missing)} not set ({path})")
        if not cfg.routes:
            raise SystemExit(f"agent config has no ROUTE entries ({path})")
        if not cfg.fingerprint and not cfg.verify_ca:
            raise SystemExit(
                "set SERVER_FINGERPRINT (or VERIFY_CA=true): the token is sent over this "
                "connection, so the server must be authenticated first"
            )
        return cfg


def build_ssl_context(cfg: Config) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not cfg.verify_ca:
        # Pinning replaces CA verification: the fingerprint is checked against
        # the presented certificate right after the handshake.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_fingerprint(writer: asyncio.StreamWriter, expected: str) -> None:
    sslobj = writer.get_extra_info("ssl_object")
    if sslobj is None:
        raise ConnectionError("connection is not TLS")
    der = sslobj.getpeercert(binary_form=True)
    actual = hashlib.sha256(der).hexdigest()
    if actual != expected:
        raise ConnectionError(
            f"server certificate fingerprint mismatch (expected {expected[:16]}…, got {actual[:16]}…)"
        )


class Session:
    def __init__(self, cfg: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.cfg = cfg
        self.reader = reader
        self.writer = writer
        self.targets: Dict[bytes, asyncio.StreamWriter] = {}
        self.pumps: Dict[bytes, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def send(self, msg_type: int, conn_id: bytes, payload: bytes = b"") -> None:
        async with self._lock:
            await send_frame(self.writer, msg_type, conn_id, payload)

    async def pump_target(self, conn_id: bytes, target_reader: asyncio.StreamReader) -> None:
        """Relay the local server's response back up the tunnel."""
        try:
            while True:
                chunk = await target_reader.read(4096)
                if not chunk:
                    break
                await self.send(MSG_DATA, conn_id, chunk)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("local read failed for %s: %s", conn_id.hex()[:8], exc)
        finally:
            try:
                await self.send(MSG_CLOSE, conn_id)
            except Exception:
                pass
            self.close_conn(conn_id)

    def close_conn(self, conn_id: bytes) -> None:
        writer = self.targets.pop(conn_id, None)
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
        task = self.pumps.pop(conn_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def open_target(self, conn_id: bytes, payload: bytes) -> None:
        info = parse_json(payload) if payload else {}
        domain = str(info.get("domain", "")).lower()
        route = self.cfg.routes.get(domain)
        if route is None:
            log.warning("server asked for unknown domain %r", domain)
            await self.send(MSG_CONNECT, conn_id, json.dumps({"ok": False}).encode("utf-8"))
            return
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(route["host"], route["port"]), 8.0
            )
        except Exception as exc:
            log.warning("cannot reach local target %s:%s for %s: %s",
                        route["host"], route["port"], domain, exc)
            await self.send(MSG_CONNECT, conn_id, json.dumps({"ok": False}).encode("utf-8"))
            return
        self.targets[conn_id] = target_writer
        self.pumps[conn_id] = asyncio.create_task(self.pump_target(conn_id, target_reader))
        await self.send(MSG_CONNECT, conn_id, json.dumps({"ok": True}).encode("utf-8"))

    async def keepalive(self) -> None:
        while True:
            await asyncio.sleep(KEEPALIVE_SECONDS)
            await self.send(MSG_PING, ZERO_ID)

    async def run(self) -> None:
        ka = asyncio.create_task(self.keepalive())
        try:
            while True:
                msg_type, conn_id, payload = await read_frame(self.reader)
                if msg_type == MSG_CONNECT:
                    asyncio.create_task(self.open_target(conn_id, payload))
                elif msg_type == MSG_DATA:
                    writer = self.targets.get(conn_id)
                    if writer is not None and not writer.is_closing():
                        writer.write(payload)
                        await writer.drain()
                elif msg_type == MSG_CLOSE:
                    self.close_conn(conn_id)
                elif msg_type == MSG_PONG:
                    pass
                else:
                    log.debug("ignoring frame type %s", msg_type)
        finally:
            ka.cancel()
            for conn_id in list(self.targets):
                self.close_conn(conn_id)


async def connect_once(cfg: Config) -> None:
    ctx = build_ssl_context(cfg)
    log.info("connecting to %s:%s", cfg.server_host, cfg.server_port)
    reader, writer = await asyncio.open_connection(
        cfg.server_host, cfg.server_port, ssl=ctx, server_hostname=cfg.server_host
    )
    try:
        if not cfg.verify_ca:
            check_fingerprint(writer, cfg.fingerprint)

        await send_json(writer, MSG_AUTH, ZERO_ID, {
            "token": cfg.token,
            "routes": {d: r for d, r in cfg.routes.items()},
        })
        msg_type, _, payload = await asyncio.wait_for(read_frame(reader), 15.0)
        if msg_type != MSG_AUTH_RESP:
            raise ConnectionError("server did not answer the auth frame")
        resp = parse_json(payload)
        if resp.get("status") != "accepted":
            raise ConnectionError(f"authentication rejected: {resp.get('reason', 'no reason given')}")

        log.info("tunnel established over TLS; serving %s", resp.get("domains"))
        await Session(cfg, reader, writer).run()
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    cfg = Config.load(CONFIG_PATH)
    log.info("routes: %s", {d: f"{r['host']}:{r['port']}" for d, r in cfg.routes.items()})
    backoff = BACKOFF_START
    while True:
        try:
            await connect_once(cfg)
            log.warning("tunnel closed by server; reconnecting")
            backoff = BACKOFF_START
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A private origin is often behind flaky egress, so never exit:
            # retry with backoff until the WAF is reachable again.
            log.error("tunnel attempt failed: %s", exc)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, BACKOFF_MAX)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("agent stopped")
