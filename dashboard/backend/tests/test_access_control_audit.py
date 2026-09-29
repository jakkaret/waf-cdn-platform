"""Tenant isolation regressions found in the 2026-09-28 access-control audit.

Each test sets up two real accounts through the API (the first registered user
is the admin, the second a viewer who owns one origin/domain) and checks that
the viewer only gets their own data from endpoints that used to return every
tenant's.
"""
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import cdn as cdn_module
from api import logs as logs_module
from api import origins as origins_module
from api import rate_limits as rate_limits_module
from api import rules as rules_module
from api import threshold_proposals as proposals_module
from services.rate_limiter import limiter


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    for module in (auth_module, origins_module, rules_module, cdn_module, rate_limits_module, proposals_module, logs_module):
        test_app.include_router(module.router)
    return test_app


@pytest.fixture()
def accounts(client: TestClient, register_user, auth_header):
    admin = register_user(email="ac-admin@example.com", username="ac_admin")
    viewer = register_user(email="ac-viewer@example.com", username="ac_viewer", role="viewer")
    admin_h = auth_header(admin["access_token"])
    viewer_h = auth_header(viewer["access_token"])
    origin_id = client.post("/api/origins", json={"label": "Mine", "ip": "203.0.113.40", "port": 80}, headers=viewer_h).json()["id"]
    tenant_service_module.db.domains_table.put_item(Item={"id": "ac-dom-1", "origin_id": origin_id, "domain_name": "mine.example.com", "dns_verified": True})
    tenant_service_module.invalidate_tenant_cache()
    return admin_h, viewer_h


BLAST = {"variable": "REQUEST_URI", "operator": "@rx test", "severity": "CRITICAL"}


def test_blast_radius_is_admin_only(client, accounts, monkeypatch):
    admin_h, viewer_h = accounts
    sim = MagicMock(return_value={"success": True, "samples": []})
    monkeypatch.setattr(rules_module.blast_radius_service, "simulate", sim)
    assert client.post("/api/rules/blast-radius", json=BLAST, headers=viewer_h).status_code == 403
    assert client.post("/api/rules/blast-radius/export", json=BLAST, headers=viewer_h).status_code == 403
    assert sim.call_count == 0, "a viewer must not trigger a replay of every tenant's traffic"
    assert client.post("/api/rules/blast-radius", json=BLAST, headers=admin_h).status_code == 200


def test_throttled_clients_hidden_from_viewers(client, accounts, monkeypatch):
    admin_h, viewer_h = accounts
    spy = MagicMock(return_value=[{"ip": "198.51.100.9", "request_count": 50}])
    monkeypatch.setattr(rate_limits_module.service, "get_throttled_clients", spy)
    assert client.get("/api/rate-limits/throttled", headers=viewer_h).json() == {"throttled_clients": []}
    assert spy.call_count == 0
    assert client.get("/api/rate-limits/throttled", headers=admin_h).json()["throttled_clients"][0]["ip"] == "198.51.100.9"


def test_threshold_proposal_evidence_is_scoped(client, accounts, monkeypatch):
    admin_h, viewer_h = accounts
    proposal = {
        "id": "p1",
        "evidence": {
            "origins": [{"origin": "mine.example.com", "requests": 500}, {"origin": "other.example.net", "requests": 900}],
            "corroborating_origins": ["mine.example.com", "other.example.net"],
        },
    }
    monkeypatch.setattr(proposals_module.store, "list", lambda status=None: [proposal])
    monkeypatch.setattr(proposals_module.store, "get", lambda pid: proposal)
    for resp in (client.get("/api/threshold-proposals/", headers=viewer_h).json()["proposals"][0],
                 client.get("/api/threshold-proposals/p1", headers=viewer_h).json()):
        assert [o["origin"] for o in resp["evidence"]["origins"]] == ["mine.example.com"]
        assert resp["evidence"]["corroborating_origins"] == ["mine.example.com"]
        assert resp["evidence"]["hidden_origin_count"] == 1
    full = client.get("/api/threshold-proposals/p1", headers=admin_h).json()
    assert len(full["evidence"]["origins"]) == 2


def test_cdn_stats_filters_on_host_not_url(client, accounts, monkeypatch):
    _admin_h, viewer_h = accounts
    seen = []
    monkeypatch.setattr(cdn_module.ch, "connected", True)
    monkeypatch.setattr(cdn_module.ch, "query_stats", lambda sql: seen.append(sql) or [[0, 0, 0, 0, 0]], raising=False)
    fake_client = MagicMock()
    fake_client.query.side_effect = lambda sql, *a, **k: seen.append(sql) or MagicMock(result_rows=[])
    monkeypatch.setattr(cdn_module.ch, "client", fake_client, raising=False)
    client.get("/api/cdn/stats", headers=viewer_h)
    assert seen, "stats should query ClickHouse for a tenant with a domain"
    for sql in seen:
        assert "host = 'mine.example.com'" in sql
        # the old filter was a bare URL substring right after the time window;
        # url LIKE may still appear for static-asset counting and for legacy
        # host = '' rows, which is fine
        assert "HOUR AND (url LIKE '%mine.example.com%'" not in sql


def test_explain_by_id_is_tenant_scoped(client, accounts, monkeypatch):
    _admin_h, viewer_h = accounts
    seen = []
    monkeypatch.setattr(logs_module.ch, "connected", True)
    fake_client = MagicMock()
    fake_client.query.side_effect = lambda sql, parameters=None: seen.append(sql) or MagicMock(result_rows=[])
    monkeypatch.setattr(logs_module.ch, "client", fake_client, raising=False)
    client.get("/api/logs/explain/00000000-0000-0000-0000-000000000001", headers=viewer_h)
    assert seen and "host = 'mine.example.com'" in seen[0]


def test_explain_by_id_without_domains_never_queries(client, register_user, auth_header, monkeypatch):
    register_user(email="ac2-admin@example.com", username="ac2_admin")
    lonely = register_user(email="ac2-viewer@example.com", username="ac2_viewer", role="viewer")
    fake_client = MagicMock()
    monkeypatch.setattr(logs_module.ch, "connected", True)
    monkeypatch.setattr(logs_module.ch, "client", fake_client, raising=False)
    client.get("/api/logs/explain/any-id", headers=auth_header(lonely["access_token"]))
    assert fake_client.query.call_count == 0
