import json
import os
import uuid
import redis
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None


# control-api enforces the rules (cdn/control-api/rate_limit.py, P2.6) and
# reads them from here; it counts each rule per client IP in
# rate:limit:<rule id>:<ip> (a plain counter with the window as its TTL).
RULES_KEY = "waf:ratelimit:rules"
KEY_PREFIX = "rate:limit:"
_PUBLISHED_FIELDS = ("id", "name", "path_pattern", "method", "limit_count", "window_seconds", "enabled")


class RateLimitService:
    """Rate-limit rule definitions in waf.rate_limit_rules (the three default
    rules are seeded by migration 0002); request counters stay in Redis. No
    I/O at construction: built at import time in api/rate_limits.py."""

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

    def publish_rules(self) -> None:
        """Hand the enabled rules to control-api. Called after every change
        and by services/shield_sync.py's worker, so a Redis restart is
        repaired within a minute."""
        rules = [{k: rule.get(k) for k in _PUBLISHED_FIELDS} for rule in self._pg.list() if rule.get("enabled")]
        self.redis_client.set(RULES_KEY, json.dumps(rules, separators=(",", ":")))

    def _publish_quietly(self) -> None:
        try:
            self.publish_rules()
        except Exception as exc:
            logger.warning("rate-limit rules not published (shield sync retries): %s", exc)

    def add_rule(self, name: str, path_pattern: str, limit_count: int, window_seconds: int,
                 method: str = "ALL", burst: int = 0, action: str = "429") -> Dict:
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        self._pg.add(rule_id, name.strip(), path_pattern.strip(), method, limit_count, window_seconds,
                     burst, action)
        self._publish_quietly()
        return {"id": rule_id, "name": name, "path_pattern": path_pattern, "limit_count": limit_count,
                "window_seconds": window_seconds, "enabled": 1}

    def update_rule(self, rule_id: str, data: Dict) -> Optional[Dict]:
        updated = self._pg.update(rule_id, data)
        self._publish_quietly()
        return updated

    def delete_rule(self, rule_id: str) -> bool:
        deleted = self._pg.delete(rule_id)
        self._publish_quietly()
        return deleted

    def _counter_keys(self):
        """(key, rule id, ip) for control-api's request counters. Other users
        of the rate:limit: prefix (per-user quotas in api/onboarding.py and
        api/ml.py, sorted sets) are not client buckets and are skipped."""
        for key in self.redis_client.scan_iter(match=f"{KEY_PREFIX}rule_*", count=500):
            rule_id, _, ip = key[len(KEY_PREFIX):].partition(":")
            if ip:
                yield key, rule_id, ip

    def get_throttled_clients(self) -> List[Dict]:
        """Client IPs counted by a rule in its current window, busiest first."""
        if not self.redis_client:
            return []
        limits = {}
        try:
            limits = {r["id"]: int(r.get("limit_count") or 0) for r in self._pg.list()}
        except Exception as e:
            logger.warning(f"rate-limit rules unavailable for the throttled view: {e}")
        throttled = []
        try:
            for key, rule_id, ip in self._counter_keys():
                count = int(self.redis_client.get(key) or 0)
                ttl = self.redis_client.ttl(key)
                limit = limits.get(rule_id, 0)
                throttled.append({
                    "ip": ip,
                    "rule_id": rule_id,
                    "request_count": count,
                    "ttl_seconds": max(0, ttl),
                    "status": "throttled" if limit and count > limit else "active",
                    "window_sample": f"{max(0, ttl)}s left",
                })
                if len(throttled) >= 200:
                    break
            throttled.sort(key=lambda x: x["request_count"], reverse=True)
        except Exception as e:
            logger.warning(f"Error fetching throttled clients from Redis: {e}")
        return throttled[:50]

    def reset_client_limit(self, ip: str) -> bool:
        if not self.redis_client:
            return False
        ip = ip.strip()
        try:
            keys = [key for key, _rule, key_ip in self._counter_keys() if key_ip == ip]
            return bool(keys) and self.redis_client.delete(*keys) > 0
        except Exception as e:
            logger.error(f"Error resetting client rate limit in Redis: {e}")
            return False
