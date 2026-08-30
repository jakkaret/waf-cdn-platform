"""Control plane for the self-hosted private tunnel.

Three responsibilities:

  * issue a per-origin agent credential (admin, scoped to an origin the caller
    owns) — unlike a single fleet-wide token, a leak here exposes one origin;
  * answer the tunnel server's verification call when an agent authenticates;
  * report real tunnel state, read from the file the tunnel server publishes,
    so the dashboard stops asserting a status it never measured.

Credential format is `cwt_<origin_id>_<secret>`: the origin id is a lookup
key, not a secret, and only the secret half is compared — against a stored
SHA-256 digest, so the table never holds a usable credential.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services.dynamodb_service import DynamoDBService
from services.rbac import get_current_user, require_admin, verify_origin_ownership

router = APIRouter(prefix="/api/tunnel", tags=["Private Tunnel"])
db = DynamoDBService()

TUNNEL_STATE_FILE = os.getenv("TUNNEL_STATE_FILE", "/var/lib/cloudwaf-tunnel/state.json")
TOKEN_PREFIX = "cwt"
# The tunnel server is considered gone if its state file has not been refreshed
# within this window; the writer refreshes every 10s.
STATE_STALE_AFTER = 60.0


class IssueTokenRequest(BaseModel):
    origin_id: str
    domains: List[str]


class VerifyAgentRequest(BaseModel):
    token: str
    domains: List[str] = []


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _split_token(token: str):
    """Return (origin_id, secret) or (None, None) if the shape is wrong."""
    parts = token.split("_")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[1] or not parts[2]:
        return None, None
    return parts[1], parts[2]


def _normalise_domains(domains) -> List[str]:
    seen = []
    for domain in domains or []:
        text = str(domain).strip().lower()
        if text and text not in seen:
            seen.append(text)
    return seen


@router.post("/issue-token")
async def issue_agent_token(
    req: IssueTokenRequest,
    current_user: dict = Depends(require_admin),
):
    """Mint a fresh agent credential for one origin, invalidating the previous one."""
    domains = _normalise_domains(req.domains)
    if not domains:
        raise HTTPException(status_code=422, detail="At least one domain is required")

    origin = verify_origin_ownership(req.origin_id, current_user)

    secret = secrets.token_hex(32)
    token = f"{TOKEN_PREFIX}_{req.origin_id}_{secret}"
    ok = db.update_origin(req.origin_id, {
        "tunnel_token_hash": _hash_secret(secret),
        "tunnel_domains": domains,
        "tunnel_token_issued_at": int(time.time()),
    })
    if not ok:
        raise HTTPException(status_code=500, detail="Could not store the credential")

    # Returned once and never recoverable: only its digest is persisted.
    return {
        "success": True,
        "origin_id": req.origin_id,
        "origin_label": origin.get("label"),
        "domains": domains,
        "token": token,
        "note": "Store this now. It is not retrievable later; re-issue to replace it.",
    }


@router.post("/verify-agent")
async def verify_agent(req: VerifyAgentRequest):
    """Called by the tunnel server while an agent authenticates.

    Unauthenticated by design — the presented token *is* the credential being
    checked. Every failure returns the same 401 so the response cannot be used
    to probe which origins exist.
    """
    denied = HTTPException(status_code=401, detail="Invalid tunnel credential")

    origin_id, secret = _split_token(req.token or "")
    if not origin_id:
        raise denied

    origin = db.get_origin_by_id(origin_id)
    if not origin or origin.get("status") == "archived":
        raise denied

    stored = origin.get("tunnel_token_hash")
    if not stored or not hmac.compare_digest(str(stored), _hash_secret(secret)):
        raise denied

    allowed = _normalise_domains(origin.get("tunnel_domains"))
    if not allowed:
        raise denied

    requested = _normalise_domains(req.domains)
    if requested and not any(d in allowed for d in requested):
        raise denied

    return {
        "status": "authorized",
        "origin_id": origin_id,
        "label": origin.get("label"),
        "allowed_domains": allowed,
    }


@router.get("/status")
async def tunnel_status(current_user: dict = Depends(get_current_user)):
    """Real tunnel state, straight from what the tunnel server last published."""
    if not os.path.exists(TUNNEL_STATE_FILE):
        return {
            "server_running": False,
            "reason": "The tunnel server has not published any state.",
            "agents": [],
            "agent_count": 0,
        }
    try:
        with open(TUNNEL_STATE_FILE, "r") as fh:
            state = json.load(fh)
    except Exception:
        return {
            "server_running": False,
            "reason": "The tunnel server state file is unreadable.",
            "agents": [],
            "agent_count": 0,
        }

    age = time.time() - float(state.get("updated_at", 0))
    fresh = age <= STATE_STALE_AFTER
    agents = state.get("agents", [])

    if current_user.get("role") != "admin":
        owned = {
            o.get("id") for o in db.get_origins_by_user(current_user.get("user_id"))
        }
        agents = [a for a in agents if a.get("agent_id") in owned]

    return {
        "server_running": fresh,
        "reason": None if fresh else f"No state update for {age:.0f}s; the tunnel server may be down.",
        "state_age_seconds": round(age, 1),
        "agent_count": len(agents),
        "domain_count": sum(len(a.get("domains", [])) for a in agents),
        "agents": agents,
    }
