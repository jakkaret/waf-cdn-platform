"""Framing shared by the tunnel server and agent.

A frame is a 21-byte header followed by an opaque payload:

    msg_type   1 byte   one of the MSG_* constants
    conn_id   16 bytes  identifies a proxied client connection; zero for
                        session-level messages (auth, keepalive)
    length     4 bytes  payload length, big-endian

Everything rides a single long-lived TCP connection that the agent opens
outbound, so a customer origin never has to accept an inbound connection.
"""

import asyncio
import json
import struct

MSG_AUTH = 1        # agent -> server: credentials and the routes it serves
MSG_AUTH_RESP = 2   # server -> agent: accepted or rejected, with a reason
MSG_CONNECT = 3     # server -> agent: open a connection to a local target
MSG_DATA = 4        # both ways: payload bytes for one connection
MSG_CLOSE = 5       # both ways: that connection is finished
MSG_PING = 6        # agent -> server: keepalive
MSG_PONG = 7        # server -> agent: keepalive ack

HEADER = struct.Struct("!B16sI")
HEADER_LEN = HEADER.size
ZERO_ID = b"\x00" * 16

# Frames larger than this are refused rather than allocated: the length field
# is attacker-controlled on an unauthenticated connection.
MAX_PAYLOAD = 1 << 20


class ProtocolError(Exception):
    pass


async def send_frame(writer: asyncio.StreamWriter, msg_type: int, conn_id: bytes, payload: bytes = b"") -> None:
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload too large: {len(payload)}")
    writer.write(HEADER.pack(msg_type, conn_id, len(payload)) + payload)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader):
    header = await reader.readexactly(HEADER_LEN)
    msg_type, conn_id, length = HEADER.unpack(header)
    if length > MAX_PAYLOAD:
        raise ProtocolError(f"declared payload too large: {length}")
    payload = await reader.readexactly(length) if length else b""
    return msg_type, conn_id, payload


async def send_json(writer: asyncio.StreamWriter, msg_type: int, conn_id: bytes, obj) -> None:
    await send_frame(writer, msg_type, conn_id, json.dumps(obj).encode("utf-8"))


def parse_json(payload: bytes):
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"malformed JSON frame: {exc}") from exc
