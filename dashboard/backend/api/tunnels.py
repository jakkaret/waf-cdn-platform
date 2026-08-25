import os
import time
import httpx
import logging
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any, Optional, Tuple
from services.rbac import require_viewer_or_above, get_current_user
from services.tenant_service import get_user_origins_and_domains
from services.dynamodb_service import DynamoDBService
import services.origin_service as origin_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/tunnels", tags=["Private Tunnels"])
db = DynamoDBService()

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")
FRP_ADMIN_USER = os.getenv("FRP_ADMIN_USER", "admin")
FRP_ADMIN_PASS = os.getenv("FRP_ADMIN_PASS", "admin1234")

_TUNNELS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL = 4.0


def _match_proxy_to_origin(proxy_name: str, origin_label: str, origin_ip: str) -> bool:
    p_norm = proxy_name.lower().replace('-', '.').replace('_', '.')
    o_lbl_norm = origin_label.lower().replace('-', '.').replace('_', '.')
    o_ip_norm = origin_ip.lower().replace('-', '.').replace('_', '.')

    if p_norm in o_lbl_norm or p_norm in o_ip_norm or o_lbl_norm in p_norm or o_ip_norm in p_norm:
        return True
    for part in o_ip_norm.split('.'):
        if len(part) >= 4 and part in p_norm:
            return True
    return False


@router.get("/status")
async def get_tunnels_status(current_user: dict = Depends(get_current_user)):
    """
    Query FRP daemon with 4-second in-memory caching for lightning fast sub-5ms dashboard loads.
    """
    user_id = current_user.get("user_id")
    user_role = current_user.get("role")
    cache_key = f"{user_id}:{user_role}"
    now = time.time()

    # 1. Immediate cache return (< 0.1ms)
    if cache_key in _TUNNELS_CACHE:
        cached_time, cached_res = _TUNNELS_CACHE[cache_key]
        if now - cached_time < CACHE_TTL:
            return cached_res

    _, active_origins, user_domains = get_user_origins_and_domains(user_id)

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
                    "active_count": 0
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
                custom_domains = conf.get("customDomains") or conf.get("custom_domains") or []
                domain_val = custom_domains[0] if custom_domains else raw_name
                domain_lower = str(domain_val).lower()

                matching_origin = next(
                    (o for o in active_origins if _match_proxy_to_origin(raw_name, o.get("label", ""), o.get("ip", ""))),
                    None
                )
                is_user_tunnel = matching_origin is not None or any(
                    domain_lower in d or d in domain_lower for d in user_domains
                ) or (user_role == "admin")

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

                user_tunnels.append({
                    "name": raw_name,
                    "domain": domain_val,
                    "origin_id": matching_origin.get("id") if matching_origin else None,
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
            "active_count": 0
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
