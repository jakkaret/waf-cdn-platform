import os
import time
import uuid
import redis
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None


class RateLimitService:
    """Rate-limit rule definitions in waf.rate_limit_rules (the three default
    rules are seeded by migration 0002); request counters stay in Redis. No
    I/O at construction: built at import time in api/rate_limits.py and
    api/limiter.py."""

    def __init__(self):
        from services.pg_store import PgRateLimitRepository
        self._pg = PgRateLimitRepository()
        try:
            self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True, socket_connect_timeout=2)
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None

    def list_rules(self) -> List[Dict]:
        return self._pg.list()

    def add_rule(self, name: str, path_pattern: str, limit_count: int, window_seconds: int,
                 method: str = "ALL", burst: int = 0, action: str = "429") -> Dict:
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        self._pg.add(rule_id, name.strip(), path_pattern.strip(), method, limit_count, window_seconds,
                     burst, action)
        return {"id": rule_id, "name": name, "path_pattern": path_pattern, "limit_count": limit_count,
                "window_seconds": window_seconds, "enabled": 1}

    def update_rule(self, rule_id: str, data: Dict) -> Optional[Dict]:
        return self._pg.update(rule_id, data)

    def delete_rule(self, rule_id: str) -> bool:
        return self._pg.delete(rule_id)

    def get_throttled_clients(self) -> List[Dict]:
        """Scan Redis for active rate-limited clients in the sliding window."""
        if not self.redis_client:
            return []

        throttled = []
        now_ms = int(time.time() * 1000)
        try:
            # Look for keys like rate:limit:*
            keys = self.redis_client.keys("rate:limit:*")
            for key in keys[:50]:  # Limit to 50 active records
                ip = key.replace("rate:limit:", "")
                count = self.redis_client.zcard(key)
                ttl = self.redis_client.ttl(key)

                # Get oldest and newest entry
                entries = self.redis_client.zrange(key, 0, -1, withscores=True)
                if entries:
                    first_ts = int(entries[0][1])
                    last_ts = int(entries[-1][1])
                    elapsed_s = max(1, (last_ts - first_ts) // 1000)
                else:
                    elapsed_s = 1

                throttled.append({
                    "ip": ip,
                    "request_count": count,
                    "ttl_seconds": max(0, ttl),
                    "status": "throttled" if count >= 10 else "active",
                    "window_sample": f"{elapsed_s}s"
                })
            # Sort by highest request count
            throttled.sort(key=lambda x: x["request_count"], reverse=True)
        except Exception as e:
            logger.warning(f"Error fetching throttled clients from Redis: {e}")

        return throttled

    def reset_client_limit(self, ip: str) -> bool:
        if not self.redis_client:
            return False
        try:
            key = f"rate:limit:{ip.strip()}"
            deleted = self.redis_client.delete(key)
            return deleted > 0
        except Exception as e:
            logger.error(f"Error resetting client rate limit in Redis: {e}")
            return False
