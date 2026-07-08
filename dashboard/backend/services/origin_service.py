import uuid
import re
from datetime import datetime
from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

def validate_ip(ip: str) -> bool:
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ipv4_pattern.match(ip))

def create_origin(admin_user_id: str, label: str, ip: str, port: int) -> dict:
    if not validate_ip(ip):
        raise ValueError("Invalid IP address format")
    
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number")
        
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
