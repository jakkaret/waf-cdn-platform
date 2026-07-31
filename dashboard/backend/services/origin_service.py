import uuid
import re
import os
from datetime import datetime
from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

# Configurable quota — set ORIGINS_QUOTA_DEFAULT in .env to override
ORIGINS_QUOTA_DEFAULT = int(os.getenv("ORIGINS_QUOTA_DEFAULT", "5"))
DOMAINS_QUOTA_PER_ORIGIN = int(os.getenv("DOMAINS_QUOTA_PER_ORIGIN", "10"))

def validate_ip(ip: str) -> bool:
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ipv4_pattern.match(ip))

def create_origin(admin_user_id: str, label: str, ip: str, port: int) -> dict:
    if not validate_ip(ip):
        raise ValueError("Invalid IP address format")
    
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
            raise ValueError("Invalid IP address format")
        update_data["ip"] = ip
    if port is not None:
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port number")
        update_data["port"] = port
        
    return db.update_origin(origin_id, update_data)

def delete_origin(origin_id: str) -> bool:
    return db.delete_origin(origin_id)

def restore_origin(origin_id: str) -> bool:
    return db.restore_origin(origin_id)


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
