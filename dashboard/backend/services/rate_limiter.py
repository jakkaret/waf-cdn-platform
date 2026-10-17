from slowapi import Limiter
import ipaddress
import redis
import time
import os
import uuid

# Caddy and waf-nginx (containers on waf-net, 172.18.0.0/16; ufw allows :8000
# only from there) reach the backend, so request.client.host is the proxy and a
# per-IP limit becomes one global bucket: a few bad logins a minute locked
# everyone out (re-audit 2026-10-17). X-Real-IP is trusted only from these
# proxies; Caddy overwrites it with the real peer (nginx/Caddyfile header_up).
_TRUSTED_PROXIES = [
    ipaddress.ip_network(c.strip())
    for c in os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128,172.18.0.0/16").split(",")
    if c.strip()
]


def _from_trusted_proxy(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_PROXIES)


def client_ip(request) -> str:
    """The visitor's address: X-Real-IP when the peer is a trusted proxy,
    otherwise the peer itself (a direct caller cannot pick its own key)."""
    peer = request.client.host if request.client else ""
    if _from_trusted_proxy(peer):
        real = (request.headers.get("x-real-ip") or "").strip()
        try:
            return str(ipaddress.ip_address(real))
        except ValueError:
            pass
    return peer or "unknown"


limiter = Limiter(key_func=client_ip)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None

class RedisRateLimiter:
    def __init__(self):
        self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)
        
        # Redis Lua Script for Sliding Window Rate Limiting
        # KEYS[1]: rate limit key
        # ARGV[1]: current timestamp in milliseconds
        # ARGV[2]: window size in milliseconds
        # ARGV[3]: max requests allowed
        # ARGV[4]: unique member ID
        self.lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local member = ARGV[4]
        
        local clear_before = now - window
        
        -- Remove old items outside window
        redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
        
        -- Count items in window
        local current_requests = redis.call('ZCARD', key)
        
        if current_requests < limit then
            -- Add current request
            redis.call('ZADD', key, now, member)
            -- Set TTL slightly larger than window
            local ttl = math.ceil(window / 1000) + 1
            redis.call('EXPIRE', key, ttl)
            return {1, current_requests + 1}
        else
            return {0, current_requests}
        end
        """
        self.script_runner = self.redis_client.register_script(self.lua_script)

    def is_allowed(self, ip: str, limit: int, window_seconds: int, fail_open: bool = True) -> tuple[bool, int, int]:
        """
        Check if client IP is allowed within rate limit window.
        Returns:
          is_allowed: bool
          current_requests: int
          retry_after: int (seconds to wait until next slot, 0 if allowed)
        """
        key = f"rate:limit:{ip}"
        now_ms = int(time.time() * 1000)
        window_ms = window_seconds * 1000
        member = f"{now_ms}:{uuid.uuid4().hex[:6]}"
        
        try:
            allowed_flag, current_count = self.script_runner(
                keys=[key],
                args=[now_ms, window_ms, limit, member]
            )
            
            is_allowed = (allowed_flag == 1)
            retry_after = 0
            
            if not is_allowed:
                # Calculate time when the oldest request in the window expires
                oldest_requests = self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_requests:
                    _, oldest_score = oldest_requests[0]
                    expiration_time = oldest_score + window_ms
                    time_remaining_ms = expiration_time - now_ms
                    retry_after = max(1, int(time_remaining_ms / 1000))
                else:
                    retry_after = 1
                    
            return is_allowed, current_count, retry_after
            
        except Exception as e:
            print(f"[Redis Rate Limiter] Error checking limit: {e}")
            # Default fail-open (allow) keeps traffic flowing if Redis fails;
            # callers guarding abuse-prone, non-critical actions pass
            # fail_open=False to deny instead.
            if fail_open:
                return True, 0, 0
            return False, 0, 60
