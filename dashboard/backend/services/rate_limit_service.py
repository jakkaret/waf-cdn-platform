import os
import time
import uuid
import sqlite3
import redis
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "rate_limits.db"

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


class RateLimitService:
    def __init__(self):
        self._init_db()
        try:
            self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    path_pattern TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT 'ALL',
                    limit_count INTEGER NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    burst INTEGER NOT NULL DEFAULT 0,
                    action TEXT NOT NULL DEFAULT '429',       -- '429' or 'temp_ban'
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL
                )
            """)
            conn.commit()

            # Insert initial standard rules if empty
            cursor = conn.execute("SELECT COUNT(*) FROM rate_rules")
            if cursor.fetchone()[0] == 0:
                now = int(time.time())
                default_rules = [
                    (
                        "rule_auth_protect",
                        "Authentication Brute-Force Guard",
                        "/api/auth/*",
                        "POST",
                        10,
                        60,
                        2,
                        "429",
                        1,
                        now
                    ),
                    (
                        "rule_global_api",
                        "Global API Spike Protection",
                        "/api/*",
                        "ALL",
                        120,
                        60,
                        20,
                        "429",
                        1,
                        now
                    ),
                    (
                        "rule_edge_flood",
                        "Edge Anti-Flooding Shield",
                        "*",
                        "ALL",
                        50,
                        1,
                        10,
                        "429",
                        1,
                        now
                    ),
                ]
                conn.executemany("""
                    INSERT INTO rate_rules (id, name, path_pattern, method, limit_count, window_seconds, burst, action, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, default_rules)
                conn.commit()
        finally:
            conn.close()

    def list_rules(self) -> List[Dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM rate_rules ORDER BY created_at ASC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def add_rule(self, name: str, path_pattern: str, limit_count: int, window_seconds: int,
                 method: str = "ALL", burst: int = 0, action: str = "429") -> Dict:
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        now = int(time.time())
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO rate_rules (id, name, path_pattern, method, limit_count, window_seconds, burst, action, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (rule_id, name.strip(), path_pattern.strip(), method.upper(), limit_count, window_seconds, burst, action, now))
            conn.commit()
            return {
                "id": rule_id,
                "name": name,
                "path_pattern": path_pattern,
                "limit_count": limit_count,
                "window_seconds": window_seconds,
                "enabled": 1
            }
        finally:
            conn.close()

    def update_rule(self, rule_id: str, data: Dict) -> Optional[Dict]:
        conn = self._get_conn()
        try:
            fields = []
            params = []
            allowed_fields = ["name", "path_pattern", "method", "limit_count", "window_seconds", "burst", "action", "enabled"]
            for k in allowed_fields:
                if k in data:
                    fields.append(f"{k} = ?")
                    params.append(data[k])

            if not fields:
                return None

            params.append(rule_id)
            query = f"UPDATE rate_rules SET {', '.join(fields)} WHERE id = ?"
            cursor = conn.execute(query, params)
            conn.commit()
            if cursor.rowcount > 0:
                row = conn.execute("SELECT * FROM rate_rules WHERE id = ?", (rule_id,)).fetchone()
                return dict(row) if row else None
            return None
        finally:
            conn.close()

    def delete_rule(self, rule_id: str) -> bool:
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM rate_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

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
