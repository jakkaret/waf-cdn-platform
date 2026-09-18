"""ClickHouse LIKE-injection regression test.

The analytics/tenant filters interpolate a caller-supplied domain into a
ClickHouse string literal. escape_like_value() must neutralise both the quote
and the backslash that would otherwise escape it.
"""
import sys
sys.path.insert(0, "/root/waf_project/dashboard/backend")
from services.clickhouse_service import ClickHouseService, escape_like_value

PAYLOADS = [
    "x' OR 1=1 --",
    "x\\' OR 1=1 --",
    "x'; DROP TABLE access_logs; --",
    "x\\\\' UNION ALL SELECT 1 --",
    "%' OR '1'='1",
]

ch = ClickHouseService()
fails = 0
for p in PAYLOADS:
    escaped = escape_like_value(p)
    sql = f"SELECT count() FROM access_logs WHERE url LIKE '%{escaped}%'"
    try:
        rows = ch.query_stats(sql)
        n = rows[0][0] if rows else 0
        ok = n == 0                      # an inert literal matches nothing
        fails += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] payload={p!r:38s} -> rows matched={n}")
    except Exception as e:
        fails += 1
        print(f"[FAIL] payload={p!r:38s} -> query error (literal broke out?): {str(e)[:120]}")

print("\ntable still present:",
      bool(ch.query_stats("SELECT count() FROM access_logs")))
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
