import time
import logging
from typing import List, Dict, Tuple, Optional
from services.dynamodb_service import DynamoDBService

logger = logging.getLogger(__name__)
db = DynamoDBService()

_TENANT_CACHE: Dict[str, Tuple[float, Tuple[List[str], List[Dict], List[str]]]] = {}
CACHE_TTL = 3.0  # 3 seconds cache


def invalidate_tenant_cache(user_id: Optional[str] = None):
    global _TENANT_CACHE
    if user_id:
        _TENANT_CACHE.pop(user_id, None)
    else:
        _TENANT_CACHE.clear()


def get_user_origins_and_domains(user_id: str) -> Tuple[List[str], List[Dict], List[str]]:
    """
    Retrieve strictly isolated origins and domains owned by a specific user,
    cached in-memory for 3 seconds to avoid multi-second AWS DynamoDB WAN roundtrip latency.
    """
    if not user_id:
        return [], [], []

    now = time.time()
    if user_id in _TENANT_CACHE:
        cached_time, cached_val = _TENANT_CACHE[user_id]
        if now - cached_time < CACHE_TTL:
            return cached_val

    try:
        user_origins = db.get_origins_by_user(user_id)
        if not user_origins:
            result = ([], [], [])
            _TENANT_CACHE[user_id] = (now, result)
            return result

        active_origins = [o for o in user_origins if o.get("status") != "archived" and o.get("status") != "deleted"]
        if not active_origins:
            result = ([], [], [])
            _TENANT_CACHE[user_id] = (now, result)
            return result

        origin_ids = [str(o.get("id")) for o in active_origins if o.get("id")]

        # Collect all domain names registered under user's origins in domains_table
        try:
            all_domains = db.domains_table.scan().get("Items", [])
            user_registered_domains = [
                str(d.get("domain_name")).strip().lower()
                for d in all_domains
                if d.get("origin_id") in origin_ids and d.get("domain_name")
            ]
        except Exception:
            user_registered_domains = []

        # Extract domains/IPs from origin ip/label
        domain_keywords = set(user_registered_domains)
        for o in active_origins:
            ip_val = str(o.get("ip", "")).strip().lower()
            label_val = str(o.get("label", "")).strip().lower()

            if ip_val:
                domain_keywords.add(ip_val)

            if "(" in label_val and ")" in label_val:
                try:
                    extracted = label_val.split("(")[1].split(")")[0].strip()
                    if "." in extracted:
                        domain_keywords.add(extracted.lower())
                except Exception:
                    pass

        result = (origin_ids, active_origins, list(domain_keywords))
        _TENANT_CACHE[user_id] = (now, result)
        return result

    except Exception as e:
        logger.error(f"Error resolving tenant origins for user {user_id}: {e}")
        return [], [], []
