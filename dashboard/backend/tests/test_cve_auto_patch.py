"""CVE Auto-Patch (2026-09-22). match_cves_to_origins is the actual feature
-- pure, no network, no Gemini -- same split that worked for
build_incident_timeline. Built directly against a real NVD API 2.0 response
shape (fetched live 2026-09-22), not a remembered schema."""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
import services.cve_feed as cve_feed_module
from services.cve_feed import (
    match_cves_to_origins, _extract_cve_keywords, _severity_and_score,
    select_search_terms, fetch_recent_cves, NVD_MAX_SEARCH_TERMS,
)
from api import auth as auth_module
from api import ml_rules as ml_rules_module
import services.audit_log as audit_log_module


def _cve(cve_id="CVE-2026-0001", vendor="nginx", product="nginx",
         severity="HIGH", score=7.5, description="A vulnerability in nginx allows remote attackers to..."):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-09-01T00:00:00.000",
            "lastModified": "2026-09-15T00:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": severity},
                }],
            },
            "configurations": [{
                "nodes": [{
                    "operator": "OR", "negate": False,
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                        "matchCriteriaId": "x",
                    }],
                }],
            }],
        }
    }


def _origin(origin_id="origin-1", tags=None):
    return {"id": origin_id, "label": "test", "status": "active", "tech_stack_tags": tags or []}


def test_extracts_vendor_and_product_keywords_from_real_cpe_match_criteria():
    cve = _cve(vendor="wordpress", product="wordpress")["cve"]
    keywords = _extract_cve_keywords(cve)
    assert "wordpress" in keywords


def test_extracts_severity_and_score_from_real_cvss_v31_shape():
    cve = _cve(severity="CRITICAL", score=9.8)["cve"]
    severity, score = _severity_and_score(cve)
    assert severity == "CRITICAL"
    assert score == 9.8


def test_a_cve_matches_an_origin_whose_tech_stack_tag_names_the_product():
    vulns = [_cve(cve_id="CVE-2026-1111", vendor="nginx", product="nginx")]
    origins = [_origin("origin-1", tags=["nginx"]), _origin("origin-2", tags=["apache"])]

    matches = match_cves_to_origins(vulns, origins)

    assert len(matches) == 1
    assert matches[0]["cve_id"] == "CVE-2026-1111"
    assert matches[0]["origin_id"] == "origin-1"
    assert matches[0]["matched_tag"] == "nginx"


def test_a_cve_does_not_match_an_origin_with_unrelated_tags():
    vulns = [_cve(vendor="nginx", product="nginx")]
    origins = [_origin("origin-1", tags=["postgresql", "django"])]

    matches = match_cves_to_origins(vulns, origins)

    assert matches == []


def test_origins_with_no_tech_stack_tags_never_match_anything():
    vulns = [_cve(vendor="nginx", product="nginx")]
    origins = [_origin("origin-1", tags=[])]

    matches = match_cves_to_origins(vulns, origins)

    assert matches == []


def test_a_tag_with_a_version_suffix_still_matches_by_substring():
    vulns = [_cve(vendor="php", product="php")]
    origins = [_origin("origin-1", tags=["php 8.1"])]

    matches = match_cves_to_origins(vulns, origins)

    assert len(matches) == 1


def test_one_cve_can_match_multiple_origins_independently():
    vulns = [_cve(cve_id="CVE-2026-2222", vendor="nginx", product="nginx")]
    origins = [_origin("origin-1", tags=["nginx"]), _origin("origin-2", tags=["nginx"])]

    matches = match_cves_to_origins(vulns, origins)

    matched_origin_ids = {m["origin_id"] for m in matches}
    assert matched_origin_ids == {"origin-1", "origin-2"}


# ─── HTTP-level: /api/ml-rules/cve-scan ────────────────────────────────────
# rule_service is mocked throughout -- it is the REAL MLRuleService()
# singleton with a real boto3 waf_pending_rules table (~268 real unreviewed
# rows as of this writing); these tests must never touch it. Same mocking
# pattern test_dynamic_rate_limiter.py and test_ml_rules_audit.py already
# established for this exact module-level singleton.

@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(ml_rules_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _patch_audit_log_db(monkeypatch, fake_infrastructure):
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())


@pytest.fixture()
def fake_rule_service(monkeypatch):
    fake = MagicMock()
    fake.db.origins_table.scan.return_value = {"Items": []}
    fake.table.scan.return_value = {"Items": []}
    fake.create_pending_rule.side_effect = lambda rule_data, created_by: {
        **rule_data, "rule_id": f"generated-{rule_data['cve_id']}",
        "status": "pending", "created_by": created_by,
    }
    monkeypatch.setattr(ml_rules_module, "rule_service", fake)
    return fake


@pytest.fixture()
def fake_cve_fetch(monkeypatch):
    def _set(vulnerabilities):
        monkeypatch.setattr(
            ml_rules_module, "fetch_recent_cves", AsyncMock(return_value=vulnerabilities),
        )
    return _set


@pytest.fixture()
def fake_gemini_pattern(monkeypatch):
    def _set(fn_or_value):
        mock = AsyncMock(side_effect=fn_or_value) if callable(fn_or_value) else AsyncMock(return_value=fn_or_value)
        monkeypatch.setattr(ml_rules_module.gemini_service, "draft_cve_rule_pattern", mock)
    return _set


def _admin(client, register_user, auth_header):
    admin = register_user(email="cve-admin@example.com", username="cve_admin")
    return auth_header(admin["access_token"])


def test_admin_can_run_a_scan_and_it_creates_a_proposal_for_a_matching_origin(
    client, register_user, auth_header, fake_rule_service, fake_cve_fetch, fake_gemini_pattern,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {
        "Items": [_origin("origin-1", tags=["nginx"])],
    }
    fake_cve_fetch([_cve(cve_id="CVE-2026-9001", vendor="nginx", product="nginx")])
    fake_gemini_pattern(r"/nginx-exploit-path")

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["matches_found"] == 1
    assert body["proposals_created"] == 1
    assert fake_rule_service.create_pending_rule.call_count == 1
    call_args = fake_rule_service.create_pending_rule.call_args
    assert call_args.kwargs.get("created_by") == "cve-auto" or call_args.args[1] == "cve-auto"
    rule_data = call_args.args[0] if call_args.args else call_args.kwargs["rule_data"]
    assert rule_data["cve_id"] == "CVE-2026-9001"

    events = audit_log_module.get_audit_log("global", db=audit_log_module.db)
    assert any(e["action"] == "cve_scan.run" for e in events)


def test_a_non_admin_cannot_run_a_scan(client, register_user, auth_header, fake_rule_service):
    register_user(email="cve-owner@example.com", username="cve_owner_admin")  # first user = admin
    viewer = register_user(email="cve-viewer@example.com", username="cve_viewer")
    viewer_h = auth_header(viewer["access_token"])

    resp = client.post("/api/ml-rules/cve-scan", headers=viewer_h)
    assert resp.status_code == 403
    fake_rule_service.create_pending_rule.assert_not_called()


def test_scan_respects_the_hard_cap_on_proposals_per_scan(
    client, register_user, auth_header, fake_rule_service, fake_cve_fetch, fake_gemini_pattern,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {
        "Items": [_origin("origin-1", tags=["nginx"])],
    }
    ten_cves = [_cve(cve_id=f"CVE-2026-{i}", vendor="nginx", product="nginx") for i in range(10)]
    fake_cve_fetch(ten_cves)
    fake_gemini_pattern(r"/some-path")

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["matches_found"] == 10
    assert body["proposals_created"] == ml_rules_module.CVE_SCAN_MAX_PROPOSALS
    assert fake_rule_service.create_pending_rule.call_count == ml_rules_module.CVE_SCAN_MAX_PROPOSALS


def test_scan_skips_a_cve_that_already_has_a_proposal_in_the_queue(
    client, register_user, auth_header, fake_rule_service, fake_cve_fetch, fake_gemini_pattern,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {
        "Items": [_origin("origin-1", tags=["nginx"])],
    }
    fake_rule_service.table.scan.return_value = {
        "Items": [{"rule_id": "existing-1", "cve_id": "CVE-2026-9001", "status": "pending"}],
    }
    fake_cve_fetch([_cve(cve_id="CVE-2026-9001", vendor="nginx", product="nginx")])
    fake_gemini_pattern(r"/some-path")

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposals_created"] == 0
    assert body["skipped_duplicate"] == 1
    fake_rule_service.create_pending_rule.assert_not_called()


def test_scan_never_writes_a_proposal_whose_gemini_pattern_fails_to_compile(
    client, register_user, auth_header, fake_rule_service, fake_cve_fetch, fake_gemini_pattern,
):
    """The core safety hazard: an LLM-drafted regex that doesn't even
    compile must never reach the approval queue."""
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {
        "Items": [_origin("origin-1", tags=["nginx"])],
    }
    fake_cve_fetch([_cve(cve_id="CVE-2026-9001", vendor="nginx", product="nginx")])
    fake_gemini_pattern(r"(unclosed[paren")  # invalid regex

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposals_created"] == 0
    assert body["skipped_no_valid_pattern"] == 1
    fake_rule_service.create_pending_rule.assert_not_called()


def test_scan_with_no_tagged_origins_creates_nothing_and_does_not_500(
    client, register_user, auth_header, fake_rule_service, fake_cve_fetch, fake_gemini_pattern,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {"Items": []}
    fake_cve_fetch([_cve(vendor="nginx", product="nginx")])
    fake_gemini_pattern(r"/some-path")

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["matches_found"] == 0
    assert body["proposals_created"] == 0


# --- per-tag NVD search -------------------------------------------------

def test_search_terms_use_each_tags_first_word_deduplicated():
    origins = [_origin("o1", ["nginx", "PHP 8.1"]), _origin("o2", ["php", "wordpress"])]
    searched, skipped = select_search_terms(origins)
    assert searched == ["nginx", "php", "wordpress"]
    assert skipped == []


def test_search_terms_over_the_cap_are_reported_as_skipped_not_dropped_silently():
    tags = [f"prod{i}" for i in range(NVD_MAX_SEARCH_TERMS + 2)]
    searched, skipped = select_search_terms([_origin("o1", tags)])
    assert searched == tags[:NVD_MAX_SEARCH_TERMS]
    assert skipped == tags[NVD_MAX_SEARCH_TERMS:]


@pytest.fixture(autouse=True)
def _empty_keyword_cache():
    cve_feed_module._keyword_cache.clear()
    yield
    cve_feed_module._keyword_cache.clear()


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _run_fetch(monkeypatch, handler, keywords):
    monkeypatch.setattr(
        cve_feed_module.httpx, "AsyncClient",
        lambda **kw: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), **kw),
    )
    monkeypatch.setattr(cve_feed_module.asyncio, "sleep", AsyncMock())
    return asyncio.run(fetch_recent_cves(keywords, days=14))


def test_fetch_searches_nvd_once_per_keyword_and_deduplicates_by_cve_id(monkeypatch):
    seen = []

    def handler(request):
        kw = request.url.params["keywordSearch"]
        seen.append(kw)
        vulns = [_cve("CVE-2026-0001")] if kw == "nginx" else [_cve("CVE-2026-0001"), _cve("CVE-2026-0002")]
        return httpx.Response(200, json={"totalResults": len(vulns), "vulnerabilities": vulns})

    result = _run_fetch(monkeypatch, handler, ["nginx", "php"])
    assert seen == ["nginx", "php"]
    assert sorted(v["cve"]["id"] for v in result) == ["CVE-2026-0001", "CVE-2026-0002"]


def test_fetch_skips_a_failing_keyword_and_keeps_the_rest(monkeypatch):
    def handler(request):
        if request.url.params["keywordSearch"] == "nginx":
            return httpx.Response(503)
        return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [_cve("CVE-2026-0009")]})

    result = _run_fetch(monkeypatch, handler, ["nginx", "php"])
    assert [v["cve"]["id"] for v in result] == ["CVE-2026-0009"]


def test_fetch_with_no_keywords_makes_no_request(monkeypatch):
    def handler(request):
        raise AssertionError("no NVD request expected")

    assert _run_fetch(monkeypatch, handler, []) == []


def test_scan_searches_only_tag_keywords_and_reports_them(
    client, register_user, auth_header, fake_rule_service, monkeypatch, fake_gemini_pattern,
):
    admin_h = _admin(client, register_user, auth_header)
    fake_rule_service.db.origins_table.scan.return_value = {"Items": [_origin("o1", ["nginx", "php 8.1"])]}
    fetch = AsyncMock(return_value=[])
    monkeypatch.setattr(ml_rules_module, "fetch_recent_cves", fetch)

    resp = client.post("/api/ml-rules/cve-scan", headers=admin_h)
    assert resp.status_code == 200, resp.text
    assert fetch.call_args.args[0] == ["nginx", "php"]
    body = resp.json()
    assert body["keywords_searched"] == ["nginx", "php"]
    assert body["keywords_skipped"] == []


def test_fetch_reuses_cached_results_instead_of_asking_nvd_again(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request.url.params["keywordSearch"])
        return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [_cve("CVE-2026-0001")]})

    _run_fetch(monkeypatch, handler, ["nginx"])
    again = _run_fetch(monkeypatch, handler, ["nginx"])
    assert calls == ["nginx"]
    assert [v["cve"]["id"] for v in again] == ["CVE-2026-0001"]


def test_a_failed_keyword_is_not_cached(monkeypatch):
    responses = iter([httpx.Response(503), httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [_cve()]})])
    _run_fetch(monkeypatch, lambda r: next(responses), ["nginx"])
    assert len(_run_fetch(monkeypatch, lambda r: next(responses), ["nginx"])) == 1


# --- GET /api/origins/{id}/cves ---------------------------------------------

from api import origins as origins_module  # noqa: E402


@pytest.fixture()
def origins_client(monkeypatch, fake_infrastructure):
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(auth_module.router)
    app.include_router(origins_module.router)
    return TestClient(app)


def _origin_with_tags(client, auth_header, token, tags):
    resp = client.post("/api/origins", json={"label": "cve-origin", "ip": "203.0.113.60", "port": 8080}, headers=auth_header(token))
    assert resp.status_code == 200, resp.text
    origin_id = resp.json()["id"]
    upd = client.put(f"/api/origins/{origin_id}", json={"tech_stack_tags": tags}, headers=auth_header(token))
    assert upd.status_code == 200, upd.text
    return origin_id


def test_origin_cves_lists_matches_highest_score_first_for_a_viewer(
    origins_client, register_user, auth_header, monkeypatch,
):
    owner = register_user(email="cve-owner@example.com", username="cve_owner")
    viewer = register_user(email="cve-viewer@example.com", username="cve_viewer")
    origin_id = _origin_with_tags(origins_client, auth_header, owner["access_token"], ["nginx"])
    grant = origins_client.post(f"/api/origins/{origin_id}/viewers", json={"email": "cve-viewer@example.com"}, headers=auth_header(owner["access_token"]))
    assert grant.status_code == 200, grant.text
    fetch = AsyncMock(return_value=[
        _cve("CVE-2026-0001", score=5.0, severity="MEDIUM"),
        _cve("CVE-2026-0002", score=9.8, severity="CRITICAL"),
        _cve("CVE-2026-0003", vendor="microsoft", product="iis"),
    ])
    monkeypatch.setattr(origins_module, "fetch_recent_cves", fetch)

    resp = origins_client.get(f"/api/origins/{origin_id}/cves", headers=auth_header(viewer["access_token"]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [c["cve_id"] for c in body["cves"]] == ["CVE-2026-0002", "CVE-2026-0001"]
    assert body["keywords_searched"] == ["nginx"]
    assert fetch.call_args.args[0] == ["nginx"]


def test_origin_cves_is_refused_to_a_user_without_access(
    origins_client, register_user, auth_header, monkeypatch,
):
    owner = register_user(email="cve-owner2@example.com", username="cve_owner2")
    stranger = register_user(email="cve-stranger@example.com", username="cve_stranger")
    origin_id = _origin_with_tags(origins_client, auth_header, owner["access_token"], ["nginx"])
    fetch = AsyncMock(return_value=[])
    monkeypatch.setattr(origins_module, "fetch_recent_cves", fetch)

    resp = origins_client.get(f"/api/origins/{origin_id}/cves", headers=auth_header(stranger["access_token"]))
    assert resp.status_code in (403, 404)
    fetch.assert_not_called()
