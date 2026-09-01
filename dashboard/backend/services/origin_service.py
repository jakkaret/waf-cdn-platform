import uuid
import re
import os
import httpx
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.tenant_service import invalidate_tenant_cache

logger = logging.getLogger(__name__)
db = DynamoDBService()

# Configurable quota — set ORIGINS_QUOTA_DEFAULT in .env to override
ORIGINS_QUOTA_DEFAULT = int(os.getenv("ORIGINS_QUOTA_DEFAULT", "10"))
DOMAINS_QUOTA_PER_ORIGIN = int(os.getenv("DOMAINS_QUOTA_PER_ORIGIN", "10"))

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")
FRP_ADMIN_USER = os.getenv("FRP_ADMIN_USER", "admin")
FRP_ADMIN_PASS = os.getenv("FRP_ADMIN_PASS", "admin1234")


def validate_ip(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    ip_str = ip.strip()
    if ip_str.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ipv4_pattern.match(ip_str):
        parts = ip_str.split('.')
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return bool(domain_pattern.match(ip_str))


def create_origin(admin_user_id: str, label: str, ip: str, port: int) -> dict:
    if not validate_ip(ip):
        raise ValueError("Invalid IP address or domain format")
    
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number")
        
    # Check quota limit
    existing_origins = [o for o in get_origins_for_user(admin_user_id) if o.get("status") != "archived"]
    if len(existing_origins) >= ORIGINS_QUOTA_DEFAULT:
        raise ValueError(f"Origin quota exceeded. Maximum allowed: {ORIGINS_QUOTA_DEFAULT} active origins per account.")
        
    origin_id = str(uuid.uuid4())
    now = datetime.now().isoformat() + "Z"
    
    origin_data = {
        "id": origin_id,
        "admin_user_id": admin_user_id,
        "label": label,
        "ip": ip,
        "port": port,
        "status": "pending",
        "created_at": now,
        "updated_at": now
    }
    
    success = db.create_origin(origin_data)
    if not success:
        raise Exception("Failed to save origin to DynamoDB")
        
    invalidate_tenant_cache(admin_user_id)
    return origin_data


def get_origins_for_user(admin_user_id: str) -> list:
    return db.get_origins_by_user(admin_user_id)


def get_origin(origin_id: str) -> dict:
    return db.get_origin_by_id(origin_id)


def update_origin(origin_id: str, label: str = None, ip: str = None, port: int = None) -> bool:
    update_data = {"updated_at": datetime.now().isoformat() + "Z"}
    if label:
        update_data["label"] = label
    if ip:
        if not validate_ip(ip):
            raise ValueError("Invalid IP address or domain format")
        update_data["ip"] = ip
    if port is not None:
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port number")
        update_data["port"] = port
        
    success = db.update_origin(origin_id, update_data)
    if success:
        invalidate_tenant_cache()
    return success


def delete_origin(origin_id: str) -> bool:
    success = db.delete_origin(origin_id)
    if success:
        invalidate_tenant_cache()
    return success


def restore_origin(origin_id: str) -> bool:
    success = db.restore_origin(origin_id)
    if success:
        invalidate_tenant_cache()
    return success


def get_quota_info(admin_user_id: str) -> dict:
    """Return current usage vs quota limits for this user."""
    origins = get_origins_for_user(admin_user_id)
    used_origins = len([o for o in origins if o.get("status") != "archived"])
    return {
        "origins": {
            "used": used_origins,
            "max": ORIGINS_QUOTA_DEFAULT,
            "available": max(0, ORIGINS_QUOTA_DEFAULT - used_origins),
            "at_limit": used_origins >= ORIGINS_QUOTA_DEFAULT,
        },
        "domains_per_origin": {
            "max": DOMAINS_QUOTA_PER_ORIGIN,
        },
    }


async def auto_sync_tunnel_origins(user_id: str, user_role: str = "user") -> List[Dict]:
    """
    Query FRP live proxies and auto-create Origin + Domain in DynamoDB for any online tunnel
    that is not yet registered.
    """
    if not user_id:
        return []

    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            res = await client.get(
                FRP_DASHBOARD_URL,
                auth=(FRP_ADMIN_USER, FRP_ADMIN_PASS)
            )
            if res.status_code != 200:
                return []
            data = res.json()
            proxies = data.get("proxies", [])
    except Exception as e:
        logger.warning(f"FRP daemon unreachable during auto_sync_tunnel_origins: {e}")
        return []

    all_user_origins = db.get_origins_by_user(user_id)
    try:
        all_domains_items = db.domains_table.scan().get("Items", [])
    except Exception:
        all_domains_items = []
    
    created_origins = []
    need_cache_invalidation = False

    for p in proxies:
        status_val = p.get("status", "offline")
        if status_val != "online":
            continue

        conf = p.get("conf") or {}
        raw_name = p.get("name", "")
        custom_domains = conf.get("customDomains") or conf.get("custom_domains") or []
        domain_val = str(custom_domains[0] if custom_domains else raw_name).strip().lower()
        if not domain_val:
            continue

        local_ip = conf.get("localIP") or conf.get("local_ip") or "127.0.0.1"
        local_port = conf.get("localPort") or conf.get("local_port") or 80

        # Check if already exists in active or archived origins
        matched_origin = None
        for o in all_user_origins:
            o_lbl = str(o.get("label", "")).lower()
            o_ip = str(o.get("ip", "")).lower()
            o_id = str(o.get("id", ""))
            o_tunnel = str(o.get("tunnel_name", "")).lower()

            if (domain_val in o_lbl or domain_val in o_ip or domain_val == o_ip or
                raw_name.lower() in o_tunnel or raw_name.lower() in o_lbl or
                raw_name.lower() in o_ip):
                matched_origin = o
                break

        if matched_origin:
            # If archived, restore it
            if matched_origin.get("status") == "archived":
                db.update_origin(matched_origin.get("id"), {"status": "active", "updated_at": datetime.now().isoformat() + "Z"})
                need_cache_invalidation = True
            continue

        # Create new origin for this tunnel
        origin_id = str(uuid.uuid4())
        now = datetime.now().isoformat() + "Z"
        clean_label = f"Tunnel ({domain_val})"

        origin_data = {
            "id": origin_id,
            "admin_user_id": user_id,
            "label": clean_label,
            "ip": domain_val if "." in domain_val else local_ip,
            "port": int(local_port) if isinstance(local_port, (int, str)) and str(local_port).isdigit() else 80,
            "status": "active",
            "is_tunnel": True,
            "tunnel_name": raw_name,
            "created_at": now,
            "updated_at": now,
        }

        success = db.create_origin(origin_data)
        if success:
            created_origins.append(origin_data)
            all_user_origins.append(origin_data)
            need_cache_invalidation = True
            logger.info(f"Auto-created Origin {clean_label} (ID: {origin_id}) for active tunnel")

            # Also ensure domain exists in waf_domains
            if "." in domain_val and not any(str(d.get("domain_name", "")).lower() == domain_val for d in all_domains_items):
                domain_id = str(uuid.uuid4())
                domain_data = {
                    "id": domain_id,
                    "origin_id": origin_id,
                    "domain_name": domain_val,
                    "verification_token": f"waf-tunnel-{uuid.uuid4().hex[:12]}",
                    "dns_verified": True,
                    "ssl_status": "active",
                    "created_at": now,
                    "updated_at": now,
                }
                try:
                    db.domains_table.put_item(Item=domain_data)
                    all_domains_items.append(domain_data)
                    logger.info(f"Auto-created Domain {domain_val} (ID: {domain_id}) for origin {origin_id}")
                except Exception as ex:
                    logger.error(f"Failed to auto-create domain {domain_val}: {ex}")

    if need_cache_invalidation:
        invalidate_tenant_cache(user_id)

    return created_origins
