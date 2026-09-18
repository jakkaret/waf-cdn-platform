import json
import os
from datetime import datetime, timezone

import redis

# Mirrors captcha_config.py's shape exactly (same Redis backend, same
# per-origin + per-domain denormalized key pattern) -- OTP Shield is a
# sibling gate, not new architecture. See origins.py's /otp endpoints and
# cdn/control-api/otp_engine.py for the other two-thirds of this feature.
DEFAULT_LOGIN_PATHS = ["/login*", "/admin*", "/wp-login.php", "/administrator*", "/user/login*"]
DEFAULT_CONFIG = {
    "enabled": False,
    "login_paths": DEFAULT_LOGIN_PATHS,
    "clearance_ttl": 3600,
    "bypass_ips": [],
    "code_length": 6,
    "code_ttl": 300,
    # Only "email" is implemented today (cdn/control-api/email_sender.py).
    # The field exists now so adding a channel later (SMS, etc.) is a new
    # value here plus a new sender module, not a config schema change.
    "channel": "email",
}


def _client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=1,
    )


def _key_origin(origin_id: str) -> str:
    return f"waf:otp:origin:{origin_id}"


def _key_domain(domain: str) -> str:
    return f"waf:otp:domain:{domain.strip().lower().rstrip('.')}"


def _read(client, key: str):
    raw = client.get(key)
    if not raw:
        return None
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError):
        return None


def get_origin_config(origin_id: str) -> dict:
    client = _client()
    try:
        value = _read(client, _key_origin(origin_id)) or {}
    except Exception as exc:
        raise RuntimeError("OTP configuration store is unavailable") from exc
    result = dict(DEFAULT_CONFIG)
    result.update(value)
    result["origin_id"] = origin_id
    return result


def save_origin_config(origin_id: str, config: dict, domains: list[str]) -> dict:
    client = _client()
    result = dict(DEFAULT_CONFIG)
    result.update(config)
    result.update({"origin_id": origin_id, "updated_at": datetime.now(timezone.utc).isoformat()})
    try:
        pipe = client.pipeline(transaction=True)
        pipe.set(_key_origin(origin_id), json.dumps(result, separators=(",", ":")))
        for domain in domains:
            domain_value = domain.strip().lower().rstrip(".")
            if domain_value:
                domain_config = dict(result)
                domain_config["domain"] = domain_value
                pipe.set(_key_domain(domain_value), json.dumps(domain_config, separators=(",", ":")))
        pipe.execute()
    except Exception as exc:
        raise RuntimeError("OTP configuration store is unavailable") from exc
    return result


def sync_domain_config(origin_id: str, domain: str) -> None:
    client = _client()
    try:
        value = _read(client, _key_origin(origin_id))
        if value is not None:
            value["domain"] = domain.strip().lower().rstrip(".")
            client.set(_key_domain(domain), json.dumps(value, separators=(",", ":")))
    except Exception as exc:
        raise RuntimeError("OTP configuration store is unavailable") from exc
