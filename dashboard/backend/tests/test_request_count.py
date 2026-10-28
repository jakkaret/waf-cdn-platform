"""Counting requests, not access_logs rows (services/request_count.py,
docs/KNOWN_ISSUES.md 11)."""
from services.request_count import one_row_per_request_sql, requests_sql


def test_requests_count_distinct_ids_and_each_idless_row():
    sql = requests_sql("status_code = 403")
    assert "uniqExactIf(request_id, request_id != '' AND (status_code = 403))" in sql
    assert "countIf(request_id = '' AND (status_code = 403))" in sql


def test_one_row_per_request_prefers_the_row_with_the_real_rule():
    sql = one_row_per_request_sql("timestamp >= {start:DateTime}", "attack_type, rule_id")
    assert "argMax(attack_type, (rule_id NOT IN ('', 'WAF-CRS'), attack_type != '', timestamp)) AS attack_type" in sql
    assert "GROUP BY request_id" in sql
    assert "UNION ALL SELECT attack_type, rule_id FROM access_logs WHERE (timestamp >= {start:DateTime}) AND request_id = ''" in sql
