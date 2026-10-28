"""Counting requests, not access_logs rows.

One request that comes through an edge can be stored as two rows with the
same request_id (docs/KNOWN_ISSUES.md 11): usually one says WAF-CRS and the
other carries the real rule. Until the cause is fixed, pages that report how
many requests were blocked count distinct ids. Rows are never deleted: the
second row is often the only one with the real rule id. A row without an
id is its own request."""


def requests_sql(cond: str = "1") -> str:
    """ClickHouse aggregate: requests matching `cond` (a SQL condition)."""
    return f"(uniqExactIf(request_id, request_id != '' AND ({cond})) + countIf(request_id = '' AND ({cond})))"


def one_row_per_request_sql(where: str, columns: str = "attack_type") -> str:
    """A subquery with one row per request: for a duplicated id, the row that
    names a real rule (not empty, not the edge's generic WAF-CRS). `columns`
    are plain access_logs columns, comma separated."""
    cols = [c.strip() for c in columns.split(",") if c.strip()]
    pick = "(rule_id NOT IN ('', 'WAF-CRS'), attack_type != '', timestamp)"
    picked = ", ".join(f"argMax({c}, {pick}) AS {c}" for c in cols)
    plain = ", ".join(cols)
    return (f"(SELECT {picked} FROM access_logs WHERE ({where}) AND request_id != '' GROUP BY request_id "
            f"UNION ALL SELECT {plain} FROM access_logs WHERE ({where}) AND request_id = '')")
