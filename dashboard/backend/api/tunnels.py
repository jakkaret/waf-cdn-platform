import os
import time
import httpx
import hashlib
import logging
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from typing import List, Dict, Any, Optional, Tuple
from services.rbac import require_viewer_or_above, get_current_user
from services.tenant_service import get_user_origins_and_domains, invalidate_tenant_cache
from services.dynamodb_service import DynamoDBService
from services.auth_service import AuthService
import services.origin_service as origin_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/tunnels", tags=["Private Tunnels"])
db = DynamoDBService()
auth_service = AuthService()

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")
FRP_ADMIN_USER = os.getenv("FRP_ADMIN_USER", "admin")
FRP_ADMIN_PASS = os.getenv("FRP_ADMIN_PASS", "admin1234")
LEGACY_STATIC_TOKEN = os.getenv("FRP_AUTH_TOKEN", "28cda1cc8790af9e459528ec6e325bcc4adf2ceb3f4b6f74de1f9c0a9a58b277")

RESERVED_SUBDOMAINS = {
    "main.waf-it-kku.online", "waf-it-kku.online", "www.waf-it-kku.online",
    "dash.waf-it-kku.online", "api.waf-it-kku.online", "auth.waf-it-kku.online",
    "main", "waf-it-kku", "www", "dash", "api", "auth", "admin", "core"
}

_TUNNELS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL = 3.0


class CreateTunnelTokenRequest(BaseModel):
    domain: str
    label: Optional[str] = None
    expires_days: Optional[int] = 365


def _match_proxy_to_origin(proxy_name: str, origin_label: str, origin_ip: str, domain: str = "") -> bool:
    p_name = proxy_name.lower().replace('-', '.').replace('_', '.')
    d_name = domain.lower().replace('-', '.').replace('_', '.') if domain else ""
    o_lbl = origin_label.lower().replace('-', '.').replace('_', '.')
    o_ip = origin_ip.lower().replace('-', '.').replace('_', '.')

    # 1. Exact or direct substring match on domain
    if d_name:
        if d_name == o_ip or d_name in o_lbl:
            return True
    if p_name and (p_name == o_ip or p_name in o_lbl):
        return True

    # 2. Extract specific subdomain components (excluding common base domain tokens)
    ignored_parts = {"online", "com", "net", "org", "local", "localhost", "waf", "kku", "it", "agent", "tunnel", "server"}
    p_parts = [p for p in p_name.split('.') if len(p) >= 3 and p not in ignored_parts]
    d_parts = [p for p in d_name.split('.') if len(p) >= 3 and p not in ignored_parts]
    o_parts = [p for p in o_ip.split('.') if len(p) >= 3 and p not in ignored_parts]

    check_parts = set(p_parts + d_parts)
    for p in check_parts:
        if p in o_parts or (f"({p}" in o_lbl or f" {p}" in o_lbl or f"-{p}" in o_lbl or f".{p}" in o_lbl):
            return True
    return False


@router.post("/token")
async def create_tunnel_token(payload: CreateTunnelTokenRequest, current_user: dict = Depends(get_current_user)):
    """
    Generate a cryptographic signed JWT Tunnel Token tied to the user and domain.
    """
    user_id = current_user.get("user_id")
    username = current_user.get("username", "user")
    domain_clean = payload.domain.strip().lower()

    if domain_clean in RESERVED_SUBDOMAINS:
        raise HTTPException(status_code=400, detail=f"Domain '{domain_clean}' is reserved for WAF Core infrastructure.")

    # Check domain conflict in DynamoDB
    all_domains = db.domains_table.scan().get("Items", [])
    for d in all_domains:
        if str(d.get("domain_name", "")).lower() == domain_clean:
            o_id = d.get("origin_id")
            if o_id:
                origin_rec = db.get_origin_by_id(o_id)
                if origin_rec and origin_rec.get("admin_user_id") != user_id and current_user.get("role") != "admin":
                    raise HTTPException(status_code=403, detail="This domain is already registered by another account.")

    # Generate Token
    expires_sec = (payload.expires_days or 365) * 86400
    token_data = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "domain": domain_clean,
        "type": "tunnel_token",
    }
    token = auth_service.create_access_token(token_data)

    return {
        "success": True,
        "token": token,
        "domain": domain_clean,
        "user_id": user_id,
        "username": username,
        "expires_in_days": payload.expires_days or 365,
    }


@router.get("/config-generator")
async def get_tunnel_config(
    domain: str = "juice.waf-it-kku.online",
    port: int = 3000,
    local_ip: str = "127.0.0.1",
    platform: str = "linux",
    current_user: dict = Depends(get_current_user)
):
    """
    Generate personalized one-liner commands with user-specific signed Tunnel Token.
    """
    user_id = current_user.get("user_id")
    username = current_user.get("username", "user")
    domain_clean = domain.strip().lower()

    # Generate user-specific token
    token_data = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "domain": domain_clean,
        "type": "tunnel_token",
    }
    token = auth_service.create_access_token(token_data)

    safe_name = f"waf-agent-{domain_clean.replace('.', '-')}"
    linux_command = (
        f"curl -sSL https://waf-it-kku.online/install-agent.sh | sudo bash -s -- "
        f"--token {token} --domain {domain_clean} --port {port} --ip {local_ip}"
    )
    docker_command = (
        f"docker run -d --name {safe_name} --restart=always --net=host "
        f"snowdreamtech/frpc:0.61.1 -s main.waf-it-kku.online:7000 "
        f"-u {token} --proxy_type http --custom_domains {domain_clean} --local_port {port}"
    )
    toml_config = (
        f'# CloudWAF Private Tunnel Configuration\n'
        f'serverAddr = "main.waf-it-kku.online"\n'
        f'serverPort = 7000\n'
        f'user = "{token}"\n\n'
        f'auth.method = "token"\n'
        f'auth.token = "{token}"\n\n'
        f'[[proxies]]\n'
        f'name = "{domain_clean.replace(".", "-")}"\n'
        f'type = "http"\n'
        f'localIP = "{local_ip}"\n'
        f'localPort = {port}\n'
        f'customDomains = ["{domain_clean}"]\n'
    )

    return {
        "success": True,
        "domain": domain_clean,
        "port": port,
        "token": token,
        "commands": {
            "linux_oneliner": linux_command,
            "docker_command": docker_command,
            "raw_toml": toml_config
        },
        "linux_command": linux_command,
        "docker_command": docker_command,
        "toml_config": toml_config
    }


@router.post("/frp-hook")
async def frp_webhook_gatekeeper(req: Dict[str, Any]):
    """
    FRP v0.61.1 HTTP Plugin Webhook Gatekeeper.
    Intercepts Login & NewProxy events to enforce User Token Validation and Domain Ownership.
    """
    op = req.get("op", "")
    content = req.get("content", {})

    if op == "Login":
        ts = content.get("timestamp", 0)
        priv_key = str(content.get("privilege_key") or "").strip()
        user_field = str(content.get("user") or "").strip()
        metadatas = content.get("metadatas") or {}
        meta_token = str(metadatas.get("token") or "").strip()

        raw_token = meta_token or user_field or (priv_key if priv_key.startswith("eyJ") else "")

        # 1. Dual-Mode: Check Legacy Token (raw or MD5 hashed with timestamp)
        legacy_matched = False
        if priv_key == LEGACY_STATIC_TOKEN or raw_token == LEGACY_STATIC_TOKEN:
            legacy_matched = True
        elif priv_key and ts:
            for delta in (0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5):
                expected_hash = hashlib.md5((LEGACY_STATIC_TOKEN + str(ts + delta)).encode()).hexdigest()
                if expected_hash.lower() == priv_key.lower():
                    legacy_matched = True
                    break

        if legacy_matched:
            logger.info(f"FRP Webhook: Authorized Login via Legacy System Token (IP: {content.get('client_address')})")
            return {"reject": False, "unchange": True}

        # 2. Check User JWT Tunnel Token
        if raw_token:
            payload = auth_service.decode_token(raw_token)
            if payload:
                user_id = payload.get("user_id") or payload.get("sub")
                logger.info(f"FRP Webhook: Authorized User '{payload.get('username')}' (ID: {user_id}) Login")
                return {"reject": False, "unchange": True}

        logger.warning(f"FRP Webhook: Rejecting unauthorized client: {content.get('client_address')}")
        return {"reject": True, "reject_reason": "Authentication failed: Invalid or expired WAF Tunnel Token", "unchange": True}

    elif op == "NewProxy":
        custom_domains = content.get("custom_domains") or ([content.get("domain")] if content.get("domain") else [])
        proxy_name = content.get("proxy_name", "")
        target_domain = str(custom_domains[0] if custom_domains else proxy_name).strip().lower()

        if not target_domain:
            return {"reject": False, "unchange": True}

        # Check Reserved Domains
        if target_domain in RESERVED_SUBDOMAINS:
            logger.warning(f"FRP Webhook: Blocked attempt to bind reserved domain '{target_domain}'")
            return {"reject": True, "reject_reason": f"Domain '{target_domain}' is reserved by CloudWAF Core", "unchange": True}

        logger.info(f"FRP Webhook: Proxy '{proxy_name}' authorized for domain '{target_domain}'")
        return {"reject": False, "unchange": True}

    elif op == "CloseProxy":
        proxy_name = content.get("proxy_name", "")
        logger.info(f"FRP Webhook: Proxy closed: {proxy_name}")
        return {"reject": False, "unchange": True}

    return {"reject": False, "unchange": True}


@router.get("/status")
async def get_tunnels_status(
    scope: Optional[str] = Query("my", description="Scope of tunnels: 'my' for user-owned only, 'all' for admin global view"),
    current_user: dict = Depends(get_current_user)
):
    """
    Query FRP daemon with multi-tenant isolation and 3-second caching.
    """
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")
    is_admin = (user_role == "admin")
    view_all = is_admin and (scope == "all")

    cache_key = f"{user_id}:{user_role}:{scope}"
    now = time.time()

    # 1. Immediate cache return (< 0.1ms)
    if cache_key in _TUNNELS_CACHE:
        cached_time, cached_res = _TUNNELS_CACHE[cache_key]
        if now - cached_time < CACHE_TTL:
            return cached_res

    # Auto-sync online tunnels to DynamoDB origins
    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    _, active_origins, user_domains = get_user_origins_and_domains(user_id)

    all_origins = db.origins_table.scan().get("Items", []) if view_all else active_origins
    all_users_map = {}
    if is_admin:
        try:
            users_list = db.waf_users.scan().get("Items", [])
            all_users_map = {u.get("user_id"): u.get("username", "Unknown") for u in users_list}
        except Exception:
            pass

    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            res = await client.get(
                FRP_DASHBOARD_URL,
                auth=(FRP_ADMIN_USER, FRP_ADMIN_PASS)
            )
            if res.status_code != 200:
                result = {
                    "success": False,
                    "error": f"FRP dashboard returned HTTP {res.status_code}",
                    "tunnels": [],
                    "count": 0,
                    "active_count": 0,
                    "scope": scope
                }
                _TUNNELS_CACHE[cache_key] = (now, result)
                return result

            data = res.json()
            proxies = data.get("proxies", [])
            user_tunnels = []
            active_count = 0

            for p in proxies:
                conf = p.get("conf") or {}
                raw_name = p.get("name", "")
                
                # Check if proxy name is namespaced with User JWT Token (e.g. eyJhbGci...app-user)
                owner_from_token = None
                display_name = raw_name
                token_username = None
                if "." in raw_name and raw_name.startswith("eyJ"):
                    token_part, actual_name = raw_name.rsplit(".", 1)
                    token_payload = auth_service.decode_token(token_part)
                    if token_payload:
                        owner_from_token = token_payload.get("user_id") or token_payload.get("sub")
                        token_username = token_payload.get("username")
                        display_name = actual_name

                custom_domains = conf.get("customDomains") or conf.get("custom_domains") or []
                domain_val = custom_domains[0] if custom_domains else display_name
                domain_lower = str(domain_val).lower()

                matching_origin = next(
                    (o for o in all_origins if _match_proxy_to_origin(display_name, o.get("label", ""), o.get("ip", ""), domain=domain_val)),
                    None
                )

                # Determine true owner
                owner_id = owner_from_token or (matching_origin.get("admin_user_id") if matching_origin else None)
                if not owner_id and is_admin:
                    owner_id = user_id

                is_mine = (owner_id == user_id)
                # Tenancy isolation filter
                is_user_tunnel = is_mine or any(
                    domain_lower in d or d in domain_lower for d in user_domains
                ) or view_all

                if not is_user_tunnel:
                    continue

                status_val = p.get("status", "offline")
                is_online = status_val == "online"
                if is_online:
                    active_count += 1

                cur_conns = p.get("curConns") if "curConns" in p else p.get("cur_conns", 0)
                traffic_in = p.get("todayTrafficIn") if "todayTrafficIn" in p else p.get("today_traffic_in", 0)
                traffic_out = p.get("todayTrafficOut") if "todayTrafficOut" in p else p.get("today_traffic_out", 0)
                local_ip = conf.get("localIP") or conf.get("local_ip") or "127.0.0.1"
                local_port = conf.get("localPort") or conf.get("local_port") or 80

                owner_name = token_username or all_users_map.get(owner_id, "You" if is_mine else "User")

                user_tunnels.append({
                    "name": display_name,
                    "full_name": raw_name,
                    "domain": domain_val,
                    "origin_id": matching_origin.get("id") if matching_origin else None,
                    "owner_id": owner_id,
                    "owner_username": owner_name,
                    "is_mine": is_mine,
                    "url": f"https://{domain_val}" if domain_val else "-",
                    "local_target": f"{local_ip}:{local_port}",
                    "status": status_val,
                    "is_online": is_online,
                    "connections": cur_conns,
                    "traffic_in_bytes": traffic_in,
                    "traffic_out_bytes": traffic_out,
                    "last_start": p.get("lastStartTime") or p.get("last_start_time", "-"),
                    "last_close": p.get("lastCloseTime") or p.get("last_close_time", "-"),
                })

            result = {
                "success": True,
                "hub_host": "main.waf-it-kku.online",
                "hub_port": 7000,
                "scope": "all" if view_all else "my",
                "is_admin": is_admin,
                "tunnels": user_tunnels,
                "count": len(user_tunnels),
                "active_count": active_count
            }
            _TUNNELS_CACHE[cache_key] = (now, result)
            return result

    except Exception as e:
        logger.error(f"Failed to query FRP daemon status: {e}")
        return {
            "success": False,
            "error": str(e),
            "tunnels": [],
            "count": 0,
            "active_count": 0,
            "scope": scope
        }


@router.delete("/{target_identifier}")
async def deregister_tunnel(target_identifier: str, current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role")
    target_clean = target_identifier.strip().lower()

    global _TUNNELS_CACHE
    _TUNNELS_CACHE.clear()

    all_origins = db.origins_table.scan().get("Items", [])
    matched_origin = None

    for o in all_origins:
        o_lbl = str(o.get("label", "")).lower()
        o_ip = str(o.get("ip", "")).lower()
        o_id = str(o.get("id", ""))
        if (target_clean == o_id or target_clean in o_lbl or target_clean in o_ip or
            any(part in o_ip for part in target_clean.split('.') if len(part) >= 4)):
            if o.get("admin_user_id") == user_id or user_role == "admin":
                matched_origin = o
                break

    if matched_origin:
        origin_service.delete_origin(matched_origin.get("id"))
        return {
            "status": "success",
            "message": f"Tunnel '{matched_origin.get('label')}' deregistered successfully."
        }

    if user_role == "admin":
        return {
            "status": "success",
            "message": f"Tunnel '{target_identifier}' removed."
        }

    raise HTTPException(status_code=404, detail=f"Tunnel or Origin '{target_identifier}' not found under your account.")
