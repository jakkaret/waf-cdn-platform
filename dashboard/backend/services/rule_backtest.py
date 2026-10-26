"""Backtest a pending ML rule on recent traffic the WAF let through, before an admin approves it.

The offline version (ml/security_test/openappsec/backtest_rules.py) replays the benchmark's
legitimate requests through a real ModSecurity and approves only rules that match none of
them. In production the closest evidence is access_logs: requests of the last N days that
were not blocked (status not 403/429, no alert). The ML service evaluates the rule the same
way it proposed it (ml/rule_proposal.backtest_rule), so the answer is "this rule would also
have matched N of the M requests your sites served normally".

Limits the admin should know, and the API returns with the result:
  - access_logs stores the request line only (no body), so body-only matches are not seen;
  - "not blocked" is not "benign": an attack the WAF missed counts as a match too, which
    only ever overstates the risk;
  - it is a sample: the newest SAMPLE_LIMIT allowed requests of the window.

A global rule (no origin) is backtested on every tenant's traffic, since an approved one
applies to every origin; a rule with an origin is deployed for that origin only, so its
sample is that origin's own hosts (tenant_service.origin_traffic_filter) and nobody else's
traffic reaches the result. Either way the result carries counts and URL paths only: no
host, no query string, no client IP.
"""
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

SAMPLE_LIMIT = 5000
DEFAULT_DAYS = 7
MAX_DAYS = 30
MAX_EXAMPLE_PATHS = 5
SUPPORTED_GENERATORS = ("gen3-detector", "rf-regex")


def allowed_requests_sample(ch, days: int, limit: int = SAMPLE_LIMIT, scope_clause: str = "") -> list[dict]:
    """Newest requests of the window the WAF did not block, as {method, url}.
    scope_clause: a WHERE fragment built by tenant_service (never user text)."""
    if not getattr(ch, "connected", False):
        raise RuntimeError("ClickHouse is not connected")
    scope = f"\n          AND ({scope_clause})" if scope_clause else ""
    query = f"""
        SELECT method, url
        FROM access_logs
        WHERE timestamp > now() - INTERVAL {int(days)} DAY
          AND alert = 0
          AND status_code NOT IN (403, 429){scope}
        ORDER BY timestamp DESC
        LIMIT {int(limit)}
    """
    return [{"method": str(m or "GET"), "url": str(u or "/"), "body": ""} for m, u in ch.query_stats(query)]


def _path_only(url: str) -> str:
    return (urlsplit(url).path or "/")[:120]


def can_backtest(rule: dict) -> bool:
    return (rule.get("generator") or "rf-regex") in SUPPORTED_GENERATORS


async def run_backtest(rule: dict, ch, ml_url: str, ml_headers: dict, days: int = DEFAULT_DAYS) -> dict:
    """Backtest result to store on the rule. Raises ValueError for a rule the ML service cannot evaluate."""
    generator = rule.get("generator") or "rf-regex"
    if generator not in SUPPORTED_GENERATORS:
        raise ValueError(f"backtest is not available for {generator} rules")
    days = max(1, min(int(days), MAX_DAYS))
    scope_clause = ""
    if rule.get("origin_id"):
        from services.tenant_service import origin_traffic_filter
        scope_clause = origin_traffic_filter(rule["origin_id"])
    sample = allowed_requests_sample(ch, days, scope_clause=scope_clause)
    spec = {"generator": generator, "detector": rule.get("detector", ""), "pattern": rule.get("pattern", "")}

    matched, scanned, indexes = 0, 0, []
    if sample:
        async with httpx.AsyncClient() as client:
            res = await client.post(f"{ml_url}/backtest-rule", json={"rule": spec, "requests": sample},
                                    headers=ml_headers, timeout=60.0)
        if res.status_code == 422:
            raise ValueError(res.json().get("detail", "rule cannot be backtested"))
        res.raise_for_status()
        data = res.json()
        matched, scanned, indexes = int(data["matched"]), int(data["scanned"]), data.get("matched_indexes", [])

    example_paths = []
    for i in indexes:
        path = _path_only(sample[i]["url"])
        if path not in example_paths:
            example_paths.append(path)
        if len(example_paths) >= MAX_EXAMPLE_PATHS:
            break

    # ints and strings only: DynamoDB rejects Python floats
    return {
        "window_days": days,
        "scanned": scanned,
        "matched": matched,
        "example_paths": example_paths,
        "sample_limit": SAMPLE_LIMIT,
        "ran_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
