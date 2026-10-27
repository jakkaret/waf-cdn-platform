"""ML Insights: Gen 3 verdicts of mirrored traffic (services/ml_verdicts.py,
/api/ml/capture relay, GET /api/ml/insights).

The verdict buffer must only accept what the ML service's /capture answers,
the relay must keep failing open, and the read API must be scoped exactly
like the Logs page: an origin's members see only that origin's hosts, a user
with nothing to read never reaches ClickHouse. No real ClickHouse: faked."""
import types
from datetime import datetime
from typing import ClassVar
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import ml as ml_module
from api import origins as origins_module
from services import ml_verdicts as mv
from services.rate_limiter import limiter
from tests.helpers.seed import seed_domain

VERDICT = {
    "request_id": "rid-1", "host": "Shop.Example.com:443", "method": "post", "path": "/api/login",
    "query": "token=%3CREDACTED%3E", "score": 0.9932, "threshold": 0.8749, "is_attack": True,
    "detectors": ["v_sqli_libinjection"], "body_length": 88, "feature_set": "gen3-F-2026-09-29-canon2",
}


@pytest.fixture(autouse=True)
def empty_buffer(monkeypatch):
    mv._buffer.clear()
    monkeypatch.setattr(mv, "ENABLED", True)
    yield
    mv._buffer.clear()


# ------------------------------------------------------------- buffer + writer

def test_a_verdict_becomes_one_normalised_row():
    assert mv.enqueue(VERDICT) is True
    row = dict(zip(mv.COLUMNS, mv._buffer[0]))
    assert isinstance(row["timestamp"], datetime) and row["timestamp"].tzinfo is not None
    assert row["host"] == "shop.example.com"  # same normalisation as access_logs.host
    assert row["method"] == "POST" and row["is_attack"] == 1
    assert row["detectors"] == ["v_sqli_libinjection"] and row["body_length"] == 88


@pytest.mark.parametrize("bad", [
    None, "x", {}, {"score": "high"}, {"score": 1.5}, {"score": -0.1},
    {"is_anomaly": False, "attack_probability": 0.1},  # an older /capture-shaped answer, not a verdict
])
def test_anything_that_is_not_a_verdict_is_dropped(bad):
    assert mv.enqueue(bad) is False
    assert len(mv._buffer) == 0


def test_only_a_real_true_counts_as_an_attack():
    mv.enqueue({**VERDICT, "is_attack": "false"})
    assert dict(zip(mv.COLUMNS, mv._buffer[0]))["is_attack"] == 0


def test_switched_off_buffers_nothing(monkeypatch):
    monkeypatch.setattr(mv, "ENABLED", False)
    assert mv.enqueue(VERDICT) is False


def test_flush_inserts_a_batch_with_the_table_columns():
    for _ in range(3):
        mv.enqueue(VERDICT)
    ch = types.SimpleNamespace(client=MagicMock())
    assert mv.flush_once(ch) == 3
    args, kwargs = ch.client.insert.call_args
    assert args[0] == "ml_verdicts" and len(args[1]) == 3 and kwargs["column_names"] == mv.COLUMNS
    assert len(mv._buffer) == 0


def test_a_failed_insert_keeps_the_rows_for_the_next_tick():
    for i in range(3):
        mv.enqueue({**VERDICT, "request_id": f"r{i}"})
    ch = types.SimpleNamespace(client=MagicMock(insert=MagicMock(side_effect=RuntimeError("down"))))
    with pytest.raises(RuntimeError):
        mv.flush_once(ch)
    assert [r[1] for r in mv._buffer] == ["r0", "r1", "r2"]  # same order, retried next tick


# ------------------------------------------------------------------- relay

class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    answer: ClassVar[object] = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *a, **k):
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setattr(ml_module, "httpx", types.SimpleNamespace(
        AsyncClient=_Client, RequestError=httpx.RequestError, HTTPStatusError=httpx.HTTPStatusError))
    monkeypatch.setattr(ml_module, "_is_internal_relay_request", lambda request: True)
    monkeypatch.setattr(ml_module, "ML_CAPTURE_URL", "http://127.0.0.1:5000")
    app = FastAPI()
    app.include_router(ml_module.router)
    return TestClient(app)


def _mirror(client):
    return client.post("/api/ml/capture", content=b"a=1", headers={"X-Original-URI": "/x", "X-Original-Host": "a.test"})


def test_relay_buffers_the_verdict_and_still_answers_204(relay):
    _Client.answer = _Resp(200, VERDICT)
    assert _mirror(relay).status_code == 204
    assert len(mv._buffer) == 1


def test_relay_buffers_nothing_when_ml_has_no_verdict(relay):
    _Client.answer = _Resp(204)
    assert _mirror(relay).status_code == 204
    assert len(mv._buffer) == 0


def test_relay_fails_open_when_ml_is_down(relay):
    _Client.answer = httpx.ConnectError("refused")
    assert _mirror(relay).status_code == 204
    assert len(mv._buffer) == 0


def test_relay_still_refuses_callers_without_the_secret(monkeypatch):
    monkeypatch.setattr(ml_module, "INTERNAL_RELAY_SECRET", "s3cret")
    app = FastAPI()
    app.include_router(ml_module.router)
    resp = _mirror(TestClient(app))
    assert resp.status_code == 404
    assert len(mv._buffer) == 0


# --------------------------------------------------------------- read API

@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(ml_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def insights_spy(monkeypatch):
    monkeypatch.setattr(ml_module.ch, "connected", True)
    spy = MagicMock(return_value={"summary": {"total": 1}})
    monkeypatch.setattr(ml_module.ml_verdicts, "insights", spy)
    return spy


def _origin_with_domain(client, headers, label, domain):
    resp = client.post("/api/origins", json={"label": label, "ip": "203.0.113.40", "port": 8080}, headers=headers)
    assert resp.status_code == 200
    origin_id = resp.json()["id"]
    seed_domain(tenant_service_module.db, {"origin_id": origin_id, "domain_name": domain, "dns_verified": True})
    tenant_service_module.invalidate_tenant_cache()
    return origin_id


def test_zero_origin_account_gets_empty_insights_without_a_query(client, register_user, auth_header, insights_spy):
    register_user(email="mli-bootstrap@example.com", username="mli_bootstrap")
    viewer = register_user(email="mli-zero@example.com", username="mli_zero", role="viewer")
    resp = client.get("/api/ml/insights", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["total"] == 0 and body["requests"] == [] and len(body["histogram"]) == mv.HISTOGRAM_BINS
    assert insights_spy.call_count == 0


def test_owner_sees_only_their_own_hosts(client, register_user, auth_header, insights_spy):
    register_user(email="mli-bootstrap2@example.com", username="mli_bootstrap2")
    owner = register_user(email="mli-owner@example.com", username="mli_owner", role="viewer")
    headers = auth_header(owner["access_token"])
    origin_id = _origin_with_domain(client, headers, "MlInsightsApp", "mlinsights.example.com")

    resp = client.get("/api/ml/insights", params={"origin": origin_id, "hours": 168}, headers=headers)
    assert resp.status_code == 200
    _ch, scope, hours, limit, min_score = insights_spy.call_args.args
    assert scope == "((host = 'mlinsights.example.com'))"
    assert (hours, limit, min_score) == (168, 50, None)


def test_another_tenants_origin_yields_nothing(client, register_user, auth_header, insights_spy):
    register_user(email="mli-bootstrap3@example.com", username="mli_bootstrap3")
    a = register_user(email="mli-a@example.com", username="mli_a", role="viewer")
    b = register_user(email="mli-b@example.com", username="mli_b", role="viewer")
    _origin_with_domain(client, auth_header(a["access_token"]), "TenantA", "tenant-a.example.com")
    b_origin = _origin_with_domain(client, auth_header(b["access_token"]), "TenantB", "tenant-b.example.com")

    resp = client.get("/api/ml/insights", params={"origin": b_origin}, headers=auth_header(a["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["requests"] == []
    assert insights_spy.call_count == 0


def test_platform_admin_reads_through_the_admin_scope(client, register_user, auth_header, insights_spy, monkeypatch):
    admin = register_user(email="mli-admin@example.com", username="mli_admin")  # first user -> admin
    monkeypatch.setattr(ml_module, "build_tenant_origin_filter", lambda origin, domains, is_admin: "" if is_admin else "1=0")
    resp = client.get("/api/ml/insights", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200
    assert insights_spy.call_args.args[1] == ""


def test_analytics_store_down_is_503(client, register_user, auth_header, monkeypatch):
    register_user(email="mli-bootstrap4@example.com", username="mli_bootstrap4")
    owner = register_user(email="mli-owner4@example.com", username="mli_owner4", role="viewer")
    headers = auth_header(owner["access_token"])
    origin_id = _origin_with_domain(client, headers, "DownApp", "down.example.com")
    monkeypatch.setattr(ml_module.ch, "connected", False)
    assert client.get("/api/ml/insights", params={"origin": origin_id}, headers=headers).status_code == 503


@pytest.mark.parametrize("params", [{"hours": 0}, {"hours": 169}, {"limit": 500}, {"min_score": 1.5}])
def test_out_of_range_parameters_are_rejected(client, register_user, auth_header, params):
    user = register_user(email="mli-params@example.com", username="mli_params")
    assert client.get("/api/ml/insights", params=params, headers=auth_header(user["access_token"])).status_code == 422


def test_unauthenticated_is_refused(client):
    assert client.get("/api/ml/insights").status_code in (401, 403)


# ------------------------------------------------------------- the queries

class _FakeCH:
    """Answers each ml_verdicts query by what it selects; records every call."""

    def __init__(self, total=4):
        self.calls = []
        self.total = total

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        if "uniqExact(host)" in sql:
            rows = [(self.total, 1, 1, 1, 1790000000, 0.8749, "gen3-F", 1, 0)]
        elif "floor(score" in sql:
            rows = [(0, 2, 0), (19, 1, 1)]
        elif "intDiv(toUnixTimestamp" in sql:
            rows = []
        elif "arrayJoin(detectors)" in sql:
            rows = [("v_sqli_libinjection", 1)]
        elif "FROM access_logs" in sql:
            rows = [("rid-1", 200, "198.51.100.7", "TH")]
        else:
            rows = [(1790000000, "rid-1", "shop.example.com", "POST", "/api/login", "", 0.99, 0.8749, 1,
                     ["v_sqli_libinjection"], 88, "block")]
        return types.SimpleNamespace(result_rows=rows)


def test_every_query_carries_the_tenant_scope_and_bound_parameters():
    fake = _FakeCH()
    out = mv.insights(types.SimpleNamespace(client=fake), "(host = 'shop.example.com')", hours=24, limit=10)
    assert len(fake.calls) == 6
    for sql, params in fake.calls:
        assert "(host = 'shop.example.com')" in sql
        assert "{hours:UInt32}" in sql and params["hours"] == 24
    assert out["summary"]["total"] == 4 and out["summary"]["threshold"] == 0.8749
    assert (out["summary"]["blocked"], out["summary"]["challenged"]) == (1, 0)
    assert out["histogram"][0]["count"] == 2 and out["histogram"][19]["flagged"] == 1
    assert len(out["timeline"]) >= 24 and all(p["count"] == 0 for p in out["timeline"])
    assert out["detectors"] == [{"detector": "v_sqli_libinjection", "count": 1}]
    req = out["requests"][0]
    assert req["request_id"] == "rid-1" and req["status_code"] == 200 and req["client_ip"] == "198.51.100.7"
    assert req["action"] == "block"


def test_default_list_is_flagged_only_and_min_score_widens_it():
    fake = _FakeCH()
    mv.insights(types.SimpleNamespace(client=fake), "1=1", limit=10)
    assert "AND is_attack = 1" in fake.calls[4][0] and "{limit:UInt32}" in fake.calls[4][0]
    fake = _FakeCH()
    mv.insights(types.SimpleNamespace(client=fake), "1=1", limit=10, min_score=0.5)
    sql, params = fake.calls[4]
    assert "score >= {min_score:Float32}" in sql and params["min_score"] == 0.5


def test_no_scored_traffic_stops_after_the_summary_query():
    fake = _FakeCH(total=0)
    out = mv.insights(types.SimpleNamespace(client=fake), "1=1")
    assert len(fake.calls) == 1 and out["requests"] == [] and out["summary"]["total"] == 0


def test_admin_unfiltered_scope_is_a_valid_where_clause():
    fake = _FakeCH()
    mv.insights(types.SimpleNamespace(client=fake), "")
    assert all("(1=1)" in sql for sql, _ in fake.calls)
