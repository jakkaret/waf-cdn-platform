"""Gen3-rules in the dashboard (2026-10-13).

Scenario: an analysed request queues rule proposals for admin review.
  - Gen 3 decides and its detectors become the rules. The RandomForest is not used: without a
    Gen 3 model on the ML host the endpoint answers 503.
  - The same proposal coming back adds a hit to the pending rule instead of a new row
    (the queue had ~268 near-identical rows, one per flagged request).
  - When nothing is proposed, the response says why.
  - An admin can backtest a pending rule on recent allowed traffic; the result holds counts
    and URL paths only, and a viewer cannot run it.
  - An admin can reject every pending rule left by the retired RandomForest path in one call.

The ML service and ClickHouse are faked; MLRuleService runs for real on an in-memory table.
"""
import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.ml_rule_service as ml_rule_service_module
from api import auth as auth_module
from api import ml as ml_module
from api import ml_rules as ml_rules_module
from services import rule_backtest
from services.ml_rule_service import MAX_EXAMPLES, MLRuleService
from services.rate_limiter import limiter


# ---------------------------------------------------------------------------
# In-memory waf_pending_rules
# ---------------------------------------------------------------------------

class _PgRulesView:
    """What the tests read as `table.items`: the rows of waf.pending_rules
    (emptied before every test by conftest)."""

    @property
    def items(self):
        from services.pg_store import PgPendingRuleRepository
        return PgPendingRuleRepository().list()


def _make_table(monkeypatch, page_size=None):
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())
    return _PgRulesView()


@pytest.fixture()
def table(monkeypatch):
    return _make_table(monkeypatch)


def legacy_rule(n):
    return {"pattern": f"@rx /old{n}", "attack_type": "Anomaly Pattern", "source_url": f"/old?{n}",
            "generator": "rf-regex", "dedup_key": f"rf-regex:@rx /old{n}"}


def gen3_rule(detector="v_sqli_libinjection", url="/?id=1'--"):
    return {
        "pattern": "@detectSQLi", "variable": "ARGS|ARGS_NAMES|REQUEST_FILENAME", "attack_type": "SQL Injection",
        "severity": "CRITICAL", "secrule_template": 'SecRule ARGS "@detectSQLi" "id:{RULE_ID},deny"',
        "source_url": url, "source_method": "GET",
        "generator": "gen3-detector", "detector": detector, "dedup_key": f"gen3-detector:{detector}",
    }


def test_new_rule_stores_generator_and_first_hit(table):
    item = MLRuleService().create_pending_rule(gen3_rule(), created_by="ml-auto")
    assert item["generator"] == "gen3-detector"
    assert item["dedup_key"] == "gen3-detector:v_sqli_libinjection"
    assert item["hit_count"] == 1
    assert item["examples"][0]["url"] == "/?id=1'--"


def test_repeat_merges_into_the_pending_rule(table):
    service = MLRuleService()
    first = service.create_pending_rule(gen3_rule(), created_by="ml-auto")
    found = service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection")
    assert found["rule_id"] == first["rule_id"]
    for n in range(MAX_EXAMPLES + 2):
        found = service.record_hit(found, gen3_rule(url=f"/?id={n}'--"))
    stored = service.get_rule_detail(first["rule_id"])
    assert stored["hit_count"] == MAX_EXAMPLES + 3
    assert len(stored["examples"]) == MAX_EXAMPLES
    assert stored["examples"][0]["url"] == f"/?id={MAX_EXAMPLES + 1}'--"  # newest first
    assert len(table.items) == 1


def test_reviewed_rule_is_not_a_merge_target(table):
    service = MLRuleService()
    first = service.create_pending_rule(gen3_rule(), created_by="ml-auto")
    service.reject_rule(first["rule_id"], rejected_by="admin")
    assert service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection") is None
    assert service.find_pending_by_dedup_key("") is None


# ---------------------------------------------------------------------------
# predict-and-suggest against a fake ML service
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = str(self._data)

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected HTTP {self.status_code}")


class _FakeML:
    """httpx.AsyncClient stand-in that answers by ML endpoint path."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, *_a, **_k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, **_kwargs):
        path = "/" + url.rsplit("/", 1)[-1]
        self.calls.append(path)
        return self.routes[path]


@pytest.fixture()
def suggest(monkeypatch, table):
    class _AllowAll:
        def is_allowed(self, *a, **k):
            return True, 1, 0

    monkeypatch.setattr(ml_module, "_suggest_limiter", _AllowAll())

    def call(routes):
        fake = _FakeML(routes)
        monkeypatch.setattr(ml_module.httpx, "AsyncClient", fake)
        req = ml_module.PredictRequest(url="/?id=1'--", method="GET", body="")
        return asyncio.run(ml_module.predict_and_suggest(req, {"user_id": "u1"})), fake.calls

    return call


GEN3_ATTACK = _Resp(200, {"is_attack": True, "attack_probability": 0.97, "threshold": 0.8749})
GEN3_PASS = _Resp(200, {"is_attack": False, "attack_probability": 0.2, "threshold": 0.8749})


def test_gen3_attack_queues_detector_rules_then_merges_the_repeat(suggest, table):
    routes = {"/predict-gen3": GEN3_ATTACK, "/generate-rule-gen3": _Resp(200, {"rules": [gen3_rule()]})}
    out, calls = suggest(routes)
    assert calls == ["/predict-gen3", "/generate-rule-gen3"]  # no RandomForest call at all
    assert out["suggestion"] == {"engine": "gen3", "created": 1, "merged": 0, "reason": ""}
    assert out["suggested_rule"]["generator"] == "gen3-detector"
    assert out["gen3"]["is_attack"] is True

    out, _ = suggest(routes)
    assert out["suggestion"]["merged"] == 1 and out["suggestion"]["created"] == 0
    assert out["suggested_rule"]["hit_count"] == 2
    assert len(table.items) == 1


def test_gen3_says_benign_so_nothing_is_queued(suggest, table):
    out, calls = suggest({"/predict-gen3": GEN3_PASS})
    assert out["suggested_rule"] is None and out["suggested_rules"] == []
    assert out["suggestion"]["reason"] == "gen3_not_attack"
    assert calls == ["/predict-gen3"] and table.items == []


def test_gen3_flag_without_detector_is_explained(suggest, table):
    out, _ = suggest({"/predict-gen3": GEN3_ATTACK, "/generate-rule-gen3": _Resp(200, {"rules": []})})
    assert out["suggestion"]["reason"] == "gen3_no_detector" and table.items == []


def test_generator_failure_is_reported_not_swallowed(suggest, table):
    out, _ = suggest({"/predict-gen3": GEN3_ATTACK, "/generate-rule-gen3": _Resp(503, {"detail": "no libinjection"})})
    assert out["suggestion"]["reason"] == "generator_error" and table.items == []


def test_no_gen3_model_is_a_503_not_an_rf_fallback(suggest, table):
    with pytest.raises(HTTPException) as exc:
        suggest({"/predict-gen3": _Resp(503, {"detail": "no model"})})
    assert exc.value.status_code == 503
    assert table.items == []


# ---------------------------------------------------------------------------
# Backtest
# ---------------------------------------------------------------------------

class _FakeCH:
    connected = True

    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def query_stats(self, query):
        self.queries.append(query)
        return self.rows


ROWS = [("GET", "/shop/item?id=5"), ("GET", "/search?q=it%27s"), ("POST", "/search?q=o%27neil"), ("GET", "/")]


def run(rule, ch, routes, days=7):
    fake = _FakeML(routes)
    original = rule_backtest.httpx.AsyncClient
    rule_backtest.httpx.AsyncClient = fake
    try:
        return asyncio.run(rule_backtest.run_backtest(rule, ch, "http://ml", {}, days)), fake
    finally:
        rule_backtest.httpx.AsyncClient = original


def test_backtest_reports_counts_and_paths_only():
    ch = _FakeCH(ROWS)
    result, _ = run({"generator": "gen3-detector", "detector": "v_sqli_libinjection"}, ch,
                    {"/backtest-rule": _Resp(200, {"scanned": 4, "matched": 2, "matched_indexes": [1, 2]})})
    assert result["scanned"] == 4 and result["matched"] == 2
    assert result["example_paths"] == ["/search"]  # de-duplicated, no query string, no host
    assert "alert = 0" in ch.queries[0] and "NOT IN (403, 429)" in ch.queries[0]
    assert all(isinstance(v, (int, str, list)) for v in result.values())  # DynamoDB-safe


def test_backtest_window_is_clamped():
    ch = _FakeCH([])
    result, fake = run({"generator": "rf-regex", "pattern": "@rx x"}, ch, {}, days=365)
    assert result["window_days"] == rule_backtest.MAX_DAYS
    assert "INTERVAL 30 DAY" in ch.queries[0]
    assert fake.calls == []  # empty sample: nothing to send


def test_backtest_refuses_cve_rules_and_a_missing_traffic_store():
    with pytest.raises(ValueError):
        run({"generator": "cve"}, _FakeCH(ROWS), {})
    offline = _FakeCH(ROWS)
    offline.connected = False
    with pytest.raises(RuntimeError):
        run({"generator": "gen3-detector", "detector": "v_xss_libinjection"}, offline, {})


@pytest.fixture()
def rules_client() -> TestClient:
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(auth_module.router)
    app.include_router(ml_rules_module.router)
    return TestClient(app)


def test_viewer_cannot_backtest(rules_client, register_user, auth_header):
    register_user(email="bt-admin@example.com", username="bt_admin")  # first user -> admin
    viewer = register_user(email="bt-viewer@example.com", username="bt_viewer", role="viewer")
    resp = rules_client.post("/api/ml-rules/some-rule/backtest", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 403


def test_admin_backtest_stores_the_result(rules_client, register_user, auth_header, monkeypatch, table):
    service = MLRuleService()
    monkeypatch.setattr(ml_rules_module, "rule_service", service)
    rule = service.create_pending_rule(gen3_rule(), created_by="ml-auto")
    monkeypatch.setattr(ml_rules_module, "_get_ch", lambda: _FakeCH(ROWS))
    monkeypatch.setattr(rule_backtest.httpx, "AsyncClient",
                        _FakeML({"/backtest-rule": _Resp(200, {"scanned": 4, "matched": 0, "matched_indexes": []})}))
    admin = register_user(email="bt-admin2@example.com", username="bt_admin2")

    resp = rules_client.post(f"/api/ml-rules/{rule['rule_id']}/backtest?days=3", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["backtest"]["matched"] == 0
    assert service.get_rule_detail(rule["rule_id"])["backtest"]["window_days"] == 3


# ---------------------------------------------------------------------------
# Reject the retired RandomForest rules in one call
# ---------------------------------------------------------------------------

def test_reject_legacy_rejects_only_pending_rf_rules_across_pages(monkeypatch):
    table = _make_table(monkeypatch, page_size=2)
    service = MLRuleService()
    legacy = [service.create_pending_rule(legacy_rule(n)) for n in range(3)]
    service.create_pending_rule({"pattern": "@rx x", "source_url": "/old"})  # written before `generator` existed
    gen3 = service.create_pending_rule(gen3_rule())
    cve = service.create_pending_rule({"pattern": "@rx cve", "cve_id": "CVE-1"}, created_by="cve-auto")

    assert service.reject_legacy_pending("op", "retired") == {"rejected": 4, "skipped": 0}
    status = {i["rule_id"]: i["status"] for i in table.items}
    assert all(status[r["rule_id"]] == "rejected" for r in legacy)
    assert status[gen3["rule_id"]] == "pending" and status[cve["rule_id"]] == "pending"
    assert service.get_rule_detail(legacy[0]["rule_id"])["reject_reason"] == "retired"


def test_reject_legacy_endpoint_is_admin_only(rules_client, register_user, auth_header, monkeypatch, table):
    service = MLRuleService()
    monkeypatch.setattr(ml_rules_module, "rule_service", service)
    events = []
    monkeypatch.setattr(ml_rules_module.audit_log, "write_audit_event", lambda **kw: events.append(kw))
    service.create_pending_rule(legacy_rule(1))
    admin = register_user(email="lg-admin@example.com", username="lg_admin")  # first user -> admin
    viewer = register_user(email="lg-viewer@example.com", username="lg_viewer", role="viewer")

    assert rules_client.post("/api/ml-rules/reject-legacy", headers=auth_header(viewer["access_token"])).status_code == 403
    resp = rules_client.post("/api/ml-rules/reject-legacy", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200 and resp.json() == {"rejected": 1, "skipped": 0}
    assert table.items[0]["status"] == "rejected"
    assert events and events[0]["details"]["rejected"] == 1


def test_reject_legacy_leaves_an_already_approved_rule_alone(table, monkeypatch):
    service = MLRuleService()
    rule = service.create_pending_rule(legacy_rule(1))
    service.rule_manager.list_rules.return_value = []
    service.approve_rule(rule["rule_id"], approved_by="admin")
    assert service.reject_legacy_pending("op", "retired") == {"rejected": 0, "skipped": 0}
    assert table.items[0]["status"] == "approved"
