"""GET /api/analytics/summary: the numbers it returns describe one population
each and agree with each other (UX review 2026-10-28).

- suspicious_ips[].total is every request of the IP, not only its blocked ones
  (it used to equal `blocked`, so the dashboard showed 100% blocked for all).
- ai_summary quotes the top IP's own blocked count, not the platform total
  (it said "64.227.32.66 ... 31 times" while the table said 16).
- No made-up values: no 12 ms latency, no "WAF Security Filter" attack type.
"""
import asyncio
import re

import api.analytics as analytics


class FakeClickHouse:
    connected = True

    def __init__(self, latency=None, attack_rows=None):
        self.latency = latency
        self.attack_rows = attack_rows or []
        self.queries = []

    def query_stats(self, sql):
        self.queries.append(sql)
        s = " ".join(sql.split())
        if s.startswith("SELECT count() FROM access_logs") and "status_code = 403" not in s:
            return [(100,)]
        if s.startswith("SELECT count() FROM access_logs"):
            return [(31,)]
        if "count(DISTINCT client_ip)" in s:
            return [(7,)]
        if "avg(request_time_ms)" in s:
            return [(self.latency,)]
        if "GROUP BY attack_type" in s:
            return self.attack_rows
        if "GROUP BY client_ip" in s:
            return [("64.227.32.66", 40, 16), ("198.51.100.9", 15, 15)]
        if "GROUP BY country" in s:
            return []
        raise AssertionError(f"unexpected query: {s}")


def _run(monkeypatch, fake, role="viewer"):
    monkeypatch.setattr(analytics, "ch", fake)
    monkeypatch.setattr(analytics, "get_user_origins_and_domains", lambda uid: (["o1"], [{"id": "o1"}], ["shop.example"]))
    monkeypatch.setattr(analytics, "build_tenant_origin_filter", lambda origin, domains, is_admin: "host = 'shop.example'")
    return asyncio.run(analytics.get_analytics_summary(origin="ALL", current_user={"user_id": "u1", "role": role}))


def test_suspicious_ip_total_counts_all_requests_of_the_ip(monkeypatch):
    fake = FakeClickHouse(latency=20.0)
    res = _run(monkeypatch, fake)
    ip_sql = next(q for q in fake.queries if "GROUP BY client_ip" in q)
    where = ip_sql.split("WHERE", 1)[1].split("GROUP BY", 1)[0]
    assert "status_code = 403" not in where  # blocked filter is not in WHERE any more
    assert "HAVING blocked > 0" in " ".join(ip_sql.split())
    assert res["suspicious_ips"][0] == {"ip": "64.227.32.66", "total": 40, "count": 40, "blocked": 16}


def test_summary_quotes_the_top_ip_own_count(monkeypatch):
    res = _run(monkeypatch, FakeClickHouse(latency=20.0, attack_rows=[("SQL Injection", 12)]))
    text = res["ai_summary"]
    assert "31 of 100 requests" in text
    assert "64.227.32.66 (16 of its 40 requests)" in text
    assert "SQL Injection (12 requests)" in text
    # The platform total is never attributed to one IP.
    assert not re.search(r"64\.227\.32\.66[^.]*31", text)


def test_no_invented_latency_or_attack_type(monkeypatch):
    res = _run(monkeypatch, FakeClickHouse(latency=None, attack_rows=[]))
    assert res["average_latency_ms"] is None
    assert res["attack_types"] == {}
    assert "not recorded" in res["ai_summary"]


def test_offline_store_reports_no_latency(monkeypatch):
    class Offline:
        connected = False

    monkeypatch.setattr(analytics, "ch", Offline())
    monkeypatch.setattr(analytics, "get_user_origins_and_domains", lambda uid: (["o1"], [{"id": "o1"}], ["shop.example"]))
    res = asyncio.run(analytics.get_analytics_summary(origin="ALL", current_user={"user_id": "u1", "role": "viewer"}))
    assert res["source"] == "offline"
    assert res["average_latency_ms"] is None
