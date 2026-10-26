"""ML anomaly rules per origin (2026-10-26).

Scenario: an origin's Owner and Editors use Security rules > ML anomaly rules
for their own origin.
  - The list shows a non-admin only the rules of origins they are Owner,
    Editor or Viewer of -- never the global queue, another origin's rules or
    an archived origin's rules -- and a single rule they may not see is a 404.
  - Owner/Editor approve or reject; a Viewer reads only (403); a stranger gets
    404 so a rule's existence does not leak.
  - Approving an origin's rule deploys it scoped to that origin (the
    TX:waf_origin_id chain, like tenant rules), whoever approves it; a global
    rule stays global and admin-only. The audit event lands in the origin's log.
  - Proposals from the AI analyst carry the origin the caller picked, which
    they must be Owner/Editor of, and never merge across origins.

The rules directory is a temp dir with nginx -t / reload stubbed; the ML
service and ClickHouse are faked.
"""
import asyncio
from pathlib import Path

import pytest

import services.ml_rule_service as ml_rule_service_module
from api import ml as ml_module
from api import ml_rules as ml_rules_module
from db import pool
from services import audit_log, rule_backtest
from services.ml_rule_service import MLRuleService
from services.rule_manager import RuleManager, scope_ml_rule_to_origin
from tests.helpers.seed import make_domain, make_origin


def gen3_rule_text(rule_id, detector, operator="@detectSQLi"):
    """What ml/rule_proposal.gen3_rule_text writes (the ml package is not on this suite's path)."""
    return (f'SecRule ARGS|ARGS_NAMES|REQUEST_FILENAME "{operator}" \\\n'
            f'    "id:{rule_id},phase:2,deny,status:403,log,severity:CRITICAL,\\\n'
            f'    t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:lowercase,t:removeNulls,\\\n'
            f"    msg:'ML proposed rule (Gen3-rules): {detector}'\"")


GEN3_TEMPLATE = gen3_rule_text("{RULE_ID}", "v_sqli_libinjection")


@pytest.fixture()
def rules_dir(tmp_path, monkeypatch) -> Path:
    rm = RuleManager.__new__(RuleManager)
    rm.rules_dir = str(tmp_path)
    rm.test_nginx = lambda: None
    rm.reload_nginx = lambda: None
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", lambda: rm)
    return tmp_path


@pytest.fixture()
def service(rules_dir, monkeypatch) -> MLRuleService:
    svc = MLRuleService()
    monkeypatch.setattr(ml_rules_module, "rule_service", svc)
    return svc


@pytest.fixture()
def team(client, register_user, auth_header, db):
    client.app.include_router(ml_rules_module.router)
    client.app.include_router(ml_module.router)
    users = {name: register_user(email=f"mlo-{name}@example.com", username=f"mlo_{name}")
             for name in ("admin", "owner", "editor", "viewer", "stranger", "other_owner")}  # first = admin
    site_a = make_origin(users["owner"]["user"], db=db, label="shop-a")
    site_b = make_origin(users["other_owner"]["user"], db=db, label="shop-b")
    for name, role in (("editor", "editor"), ("viewer", "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)",
                   (site_a["id"], users[name]["user"]["user_id"], role))
    h = {name: auth_header(u["access_token"]) for name, u in users.items()}
    return site_a["id"], site_b["id"], h


def _rule(service, origin_id="", label="", key=None, template=GEN3_TEMPLATE):
    return service.create_pending_rule({
        "pattern": "@detectSQLi", "variable": "ARGS|ARGS_NAMES|REQUEST_FILENAME", "attack_type": "SQL Injection",
        "secrule_template": template, "source_url": "/?id=1'--", "generator": "gen3-detector",
        "detector": "v_sqli_libinjection", "dedup_key": key, "origin_id": origin_id, "origin_label": label,
    })


def _conf(rules_dir: Path, deployed_id: int) -> str:
    return (rules_dir / f"ml-{deployed_id}.conf").read_text()


# ---- who sees what --------------------------------------------------------------

def test_members_see_only_their_origins_rules_with_what_they_may_do(client, team, service):
    a, b, h = team
    mine = _rule(service, a, "shop-a")
    _rule(service, b, "shop-b")
    _rule(service)  # global queue

    owner = client.get("/api/ml-rules/", headers=h["owner"]).json()
    assert owner["is_admin"] is False
    assert [r["rule_id"] for r in owner["rules"]] == [mine["rule_id"]]
    row = owner["rules"][0]
    assert row["origin_id"] == a and row["origin_label"] == "shop-a"
    assert row["deploy_scope"] == "origin" and row["can_review"] is True and row["can_backtest"] is True

    editor = client.get("/api/ml-rules/?status=pending", headers=h["editor"]).json()["rules"]
    assert [r["can_review"] for r in editor] == [True]
    viewer = client.get("/api/ml-rules/", headers=h["viewer"]).json()["rules"]
    assert [(r["rule_id"], r["can_review"], r["can_backtest"]) for r in viewer] == [(mine["rule_id"], False, False)]
    assert client.get("/api/ml-rules/", headers=h["stranger"]).json() == {"rules": [], "is_admin": False}


def test_admin_sees_every_rule_and_the_global_one_is_global(client, team, service):
    a, b, h = team
    _rule(service, a)
    _rule(service, b)
    glob = _rule(service)
    body = client.get("/api/ml-rules/", headers=h["admin"]).json()
    assert body["is_admin"] is True and len(body["rules"]) == 3
    row = next(r for r in body["rules"] if r["rule_id"] == glob["rule_id"])
    assert row["deploy_scope"] == "global" and row["origin_id"] == "" and row["can_review"] is True


def test_a_single_rule_is_404_for_anyone_outside_its_origin(client, team, service):
    a, b, h = team
    mine, theirs, glob = _rule(service, a), _rule(service, b), _rule(service)
    assert client.get(f"/api/ml-rules/{mine['rule_id']}", headers=h["viewer"]).status_code == 200
    assert client.get(f"/api/ml-rules/{mine['rule_id']}", headers=h["stranger"]).status_code == 404
    assert client.get(f"/api/ml-rules/{theirs['rule_id']}", headers=h["owner"]).status_code == 404
    assert client.get(f"/api/ml-rules/{glob['rule_id']}", headers=h["owner"]).status_code == 404
    got = client.get(f"/api/ml-rules/{glob['rule_id']}", headers=h["admin"]).json()
    assert got["deploy_scope"] == "global" and got["can_review"] is True


def test_an_archived_origins_rules_disappear_for_its_members(client, team, service, db):
    a, _b, h = team
    mine = _rule(service, a)
    db.update_origin(a, {"status": "archived"})
    assert client.get("/api/ml-rules/", headers=h["owner"]).json()["rules"] == []
    assert client.get(f"/api/ml-rules/{mine['rule_id']}", headers=h["owner"]).status_code == 404
    assert client.post(f"/api/ml-rules/{mine['rule_id']}/approve", headers=h["owner"]).status_code == 404


# ---- review -----------------------------------------------------------------------

def test_viewer_and_stranger_cannot_review(client, team, service):
    a, _b, h = team
    rid = _rule(service, a)["rule_id"]
    r = client.post(f"/api/ml-rules/{rid}/approve", headers=h["viewer"])
    assert r.status_code == 403 and r.json()["detail"] == "Owner or Editor of this origin required"
    assert client.post(f"/api/ml-rules/{rid}/reject", json={"reason": "x"}, headers=h["viewer"]).status_code == 403
    assert client.post(f"/api/ml-rules/{rid}/approve", headers=h["stranger"]).status_code == 404
    assert client.post(f"/api/ml-rules/{rid}/reject", json={}, headers=h["stranger"]).status_code == 404
    assert service.get_rule_detail(rid)["status"] == "pending"


@pytest.mark.parametrize("who", ["editor", "owner"])
def test_owner_or_editor_approval_deploys_for_that_origin_only(client, team, service, rules_dir, who):
    a, _b, h = team
    rid = _rule(service, a)["rule_id"]
    r = client.post(f"/api/ml-rules/{rid}/approve", headers=h[who])
    assert r.status_code == 200, r.text
    deployed = r.json()["rule"]["deployed_rule_id"]
    text = _conf(rules_dir, deployed)
    assert f'SecRule TX:waf_origin_id "@streq {a}" \\\n' in text
    assert f"id:{deployed},phase:2,deny,status:403,log,severity:CRITICAL,msg:" in text
    assert f"tag:'origin:{a}',chain\"" in text
    # The original match is the chained link, transformations unchanged.
    assert ('    SecRule ARGS|ARGS_NAMES|REQUEST_FILENAME "@detectSQLi" '
            '"t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:lowercase,t:removeNulls"') in text

    events = [e for e in audit_log.get_audit_log(a, db=audit_log.db) if e["action"] == "rule.approve"]
    assert len(events) == 1 and events[0]["details"]["deploy_scope"] == "origin"
    assert not [e for e in audit_log.get_audit_log("global", db=audit_log.db) if e["action"] == "rule.approve"]


def test_owner_rejection_is_in_the_origins_audit_log(client, team, service):
    a, _b, h = team
    rid = _rule(service, a)["rule_id"]
    r = client.post(f"/api/ml-rules/{rid}/reject", json={"reason": "blocks our search"}, headers=h["owner"])
    assert r.status_code == 200
    assert service.get_rule_detail(rid)["status"] == "rejected"
    events = [e for e in audit_log.get_audit_log(a, db=audit_log.db) if e["action"] == "rule.reject"]
    assert events and events[0]["details"]["reason"] == "blocks our search"


def test_admin_approving_an_origin_rule_still_scopes_it(client, team, service, rules_dir):
    a, _b, h = team
    rid = _rule(service, a)["rule_id"]
    deployed = client.post(f"/api/ml-rules/{rid}/approve", headers=h["admin"]).json()["rule"]["deployed_rule_id"]
    assert f'"@streq {a}"' in _conf(rules_dir, deployed)
    assert [e["action"] for e in audit_log.get_audit_log(a, db=audit_log.db)
            if e["action"].startswith("rule.")] == ["rule.approve"]


def test_a_global_rule_stays_global_and_admin_only(client, team, service, rules_dir):
    _a, _b, h = team
    rid = _rule(service)["rule_id"]
    assert client.post(f"/api/ml-rules/{rid}/approve", headers=h["owner"]).status_code == 404
    deployed = client.post(f"/api/ml-rules/{rid}/approve", headers=h["admin"]).json()["rule"]["deployed_rule_id"]
    text = _conf(rules_dir, deployed)
    assert "waf_origin_id" not in text and "chain" not in text
    assert text.count("SecRule ") == 1
    events = [e for e in audit_log.get_audit_log("global", db=audit_log.db) if e["action"].startswith("rule.")]
    assert [e["action"] for e in events] == ["rule.approve"] and events[0]["details"]["deploy_scope"] == "global"


def test_admin_only_actions_stay_admin_only(client, team, service):
    a, _b, h = team
    rid = _rule(service, a)["rule_id"]
    assert client.delete(f"/api/ml-rules/{rid}", headers=h["owner"]).status_code == 403
    assert client.post("/api/ml-rules/reject-legacy", headers=h["owner"]).status_code == 403
    assert client.post("/api/ml-rules/cve-scan", headers=h["owner"]).status_code == 403


def test_a_rule_whose_origin_changed_is_not_approved(team, service):
    a, b, _h = team
    rid = _rule(service, a)["rule_id"]
    with pytest.raises(ValueError):
        service.approve_rule(rid, approved_by="x", expected_origin_id=b)
    with pytest.raises(ValueError):
        service.approve_rule(rid, approved_by="x", expected_origin_id="")
    assert service.get_rule_detail(rid)["status"] == "pending"


def test_an_origin_can_have_only_so_many_approved_ml_rules(client, team, service, monkeypatch):
    a, _b, h = team
    monkeypatch.setattr(ml_rule_service_module, "MAX_APPROVED_RULES_PER_ORIGIN", 1)
    first, second = _rule(service, a, key="k1")["rule_id"], _rule(service, a, key="k2")["rule_id"]
    assert client.post(f"/api/ml-rules/{first}/approve", headers=h["owner"]).status_code == 200
    r = client.post(f"/api/ml-rules/{second}/approve", headers=h["owner"])
    assert r.status_code == 400 and "at most 1" in r.json()["detail"]
    assert service.get_rule_detail(second)["status"] == "pending"


# ---- backtest -------------------------------------------------------------------------

class _FakeCH:
    connected = True

    def __init__(self):
        self.queries = []

    def query_stats(self, query):
        self.queries.append(query)
        return []


def test_backtest_of_an_origin_rule_reads_only_that_origins_traffic(client, team, service, monkeypatch, db):
    a, _b, h = team
    make_domain(db.get_origin_by_id(a), "shop-a.example.com", db=db)
    rid = _rule(service, a)["rule_id"]
    ch = _FakeCH()
    monkeypatch.setattr(ml_rules_module, "_get_ch", lambda: ch)
    assert client.post(f"/api/ml-rules/{rid}/backtest", headers=h["viewer"]).status_code == 403
    assert client.post(f"/api/ml-rules/{rid}/backtest", headers=h["stranger"]).status_code == 404
    r = client.post(f"/api/ml-rules/{rid}/backtest", headers=h["editor"])
    assert r.status_code == 200, r.text
    assert "host = 'shop-a.example.com'" in ch.queries[0]


def test_backtest_of_an_origin_without_verified_hosts_matches_nothing(team, service):
    a, _b, _h = team
    ch = _FakeCH()
    result = asyncio.run(rule_backtest.run_backtest(_rule(service, a), ch, "http://ml", {}))
    assert "AND (1=0)" in ch.queries[0] and result["scanned"] == 0


# ---- proposals from the AI analyst ------------------------------------------------------

def test_dedup_never_merges_across_origins(team, service):
    a, b, _h = team
    rows = [_rule(service, oid, key="gen3-detector:v_sqli_libinjection") for oid in (a, a, b, "", "")]
    assert len({r["rule_id"] for r in rows}) == 3
    assert service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection", a)["rule_id"] == rows[0]["rule_id"]
    assert service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection", b)["rule_id"] == rows[2]["rule_id"]
    assert service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection")["rule_id"] == rows[3]["rule_id"]
    assert service.find_pending_by_dedup_key("gen3-detector:v_sqli_libinjection", "not-a-uuid") is None
    assert {r["rule_id"]: r["hit_count"] for r in service.list_rules("pending")}[rows[0]["rule_id"]] == 2


class _Resp:
    def __init__(self, status_code, data):
        self.status_code, self._data, self.text = status_code, data, str(data)

    def json(self):
        return self._data


class _FakeML:
    def __init__(self, routes):
        self.routes = routes

    def __call__(self, *_a, **_k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, **_kwargs):
        return self.routes["/" + url.rsplit("/", 1)[-1]]


@pytest.fixture()
def fake_ml(monkeypatch, rules_dir):
    class _AllowAll:
        def is_allowed(self, *a, **k):
            return True, 1, 0

    monkeypatch.setattr(ml_module, "_suggest_limiter", _AllowAll())
    proposal = {"pattern": "@detectSQLi", "variable": "ARGS|ARGS_NAMES|REQUEST_FILENAME",
                "attack_type": "SQL Injection", "severity": "CRITICAL", "secrule_template": GEN3_TEMPLATE,
                "source_url": "/?id=1'--", "source_method": "GET", "generator": "gen3-detector",
                "detector": "v_sqli_libinjection", "dedup_key": "gen3-detector:v_sqli_libinjection",
                # Whatever the ML service says, the origin comes from the caller's choice.
                "origin_id": "ignored"}
    monkeypatch.setattr(ml_module.httpx, "AsyncClient", _FakeML({
        "/predict-gen3": _Resp(200, {"is_attack": True, "attack_probability": 0.97, "threshold": 0.87}),
        "/generate-rule-gen3": _Resp(200, {"rules": [proposal]}),
    }))


def test_suggest_for_an_origin_needs_owner_or_editor(client, team, fake_ml):
    a, b, h = team
    body = {"url": "/?id=1'--", "method": "GET", "origin_id": a}
    assert client.post("/api/ml/predict-and-suggest", json=body, headers=h["viewer"]).status_code == 403
    assert client.post("/api/ml/predict-and-suggest", json=body, headers=h["stranger"]).status_code == 403
    assert client.post("/api/ml/predict-and-suggest", json={**body, "origin_id": b},
                       headers=h["owner"]).status_code == 403
    assert client.post("/api/ml/predict-and-suggest", json={**body, "origin_id": "no-such-origin"},
                       headers=h["owner"]).status_code == 403
    assert MLRuleService().list_rules() == []


def test_suggest_for_an_origin_lands_in_that_origins_queue_and_merges_there_only(client, team, fake_ml):
    a, _b, h = team
    body = {"url": "/?id=1'--", "method": "GET", "origin_id": a}
    first = client.post("/api/ml/predict-and-suggest", json=body, headers=h["editor"])
    assert first.status_code == 200, first.text
    out = first.json()
    assert out["suggestion"]["origin_id"] == a and out["suggestion"]["created"] == 1
    assert out["suggested_rule"]["origin_id"] == a and out["suggested_rule"]["origin_label"] == "shop-a"

    again = client.post("/api/ml/predict-and-suggest", json=body, headers=h["owner"]).json()
    assert again["suggestion"]["merged"] == 1 and again["suggested_rule"]["hit_count"] == 2

    # The same detector without an origin goes to the global queue, not into the origin's rule.
    glob = client.post("/api/ml/predict-and-suggest", json={"url": "/?id=1'--"}, headers=h["admin"]).json()
    assert glob["suggestion"] == {"engine": "gen3", "created": 1, "merged": 0, "reason": "", "origin_id": ""}
    assert glob["suggested_rule"]["origin_id"] == ""

    listed = client.get("/api/ml-rules/", headers=h["owner"]).json()["rules"]
    assert [(r["origin_id"], r["hit_count"]) for r in listed] == [(a, 2)]


def test_a_merge_into_the_global_queue_returns_only_the_callers_own_examples(client, team, service, fake_ml):
    _a, _b, h = team
    body = {"url": "/?id=1'--", "method": "GET"}
    first = client.post("/api/ml/predict-and-suggest", json=body, headers=h["owner"]).json()
    rid = first["suggested_rule"]["rule_id"]
    # An admin backtest stored on the global rule samples every origin's traffic.
    service.save_backtest(service.get_rule_detail(rid), {"matched": 1, "example_paths": ["/other-tenant/admin"]})

    out = client.post("/api/ml/predict-and-suggest", json=body, headers=h["stranger"]).json()
    rule = out["suggested_rule"]
    assert out["suggestion"]["merged"] == 1 and rule["rule_id"] == rid
    assert [e["requested_by"] for e in rule["examples"]] == ["mlo_stranger"]
    assert "backtest" not in rule and "mlo_owner" not in str(out)

    # The admin's queue keeps every example and the backtest.
    full = client.get(f"/api/ml-rules/{rid}", headers=h["admin"]).json()
    assert {e["requested_by"] for e in full["examples"]} == {"mlo_owner", "mlo_stranger"}
    assert full["backtest"]["example_paths"] == ["/other-tenant/admin"]


# ---- revoking an approved rule (2026-10-27) --------------------------------------------------

def _approved(client, h, service, origin_id="", key=None, who="admin"):
    rid = _rule(service, origin_id, key=key)["rule_id"]
    r = client.post(f"/api/ml-rules/{rid}/approve", headers=h[who])
    assert r.status_code == 200, r.text
    return rid, r.json()["rule"]["deployed_rule_id"]


def test_owner_revokes_an_origin_rule_and_its_file_leaves_the_waf(client, team, service, rules_dir):
    a, _b, h = team
    rid, deployed = _approved(client, h, service, a, who="owner")
    rows = {who: client.get(f"/api/ml-rules/{rid}", headers=h[who]).json() for who in ("owner", "editor", "viewer")}
    assert [rows[w]["can_revoke"] for w in ("owner", "editor", "viewer")] == [True, True, False]

    r = client.post(f"/api/ml-rules/{rid}/revoke", json={"reason": "false positives on /search"}, headers=h["editor"])
    assert r.status_code == 200, r.text
    assert r.json()["rule"]["status"] == "revoked" and r.json()["rule"]["can_revoke"] is False
    assert not (rules_dir / f"ml-{deployed}.conf").exists()
    row = service.get_rule_detail(rid)
    assert (row["status"], row["revoked_by"], row["revoke_reason"]) == ("revoked", "mlo_editor", "false positives on /search")
    assert row["deployed_rule_id"] == deployed and row["revoked_at"]
    events = [e for e in audit_log.get_audit_log(a, db=audit_log.db) if e["action"] == "rule.revoke"]
    assert len(events) == 1 and events[0]["details"]["deployed_rule_id"] == deployed


def test_who_may_not_revoke(client, team, service):
    a, b, h = team
    rid, _ = _approved(client, h, service, a)
    pending = _rule(service, a, key="still-pending")["rule_id"]
    r = client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["viewer"])
    assert r.status_code == 403 and r.json()["detail"] == "Owner or Editor of this origin required"
    assert client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["stranger"]).status_code == 404
    assert client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["other_owner"]).status_code == 404
    assert client.post(f"/api/ml-rules/{pending}/revoke", json={}, headers=h["owner"]).status_code == 400
    glob, _ = _approved(client, h, service, key="global")
    assert client.post(f"/api/ml-rules/{glob}/revoke", json={}, headers=h["owner"]).status_code == 404
    assert service.get_rule_detail(rid)["status"] == "approved"


def test_a_rule_written_for_every_origin_is_revoked_by_the_admin_only(client, team, service, rules_dir):
    a, _b, h = team
    rid, deployed = _approved(client, h, service, a)
    # A CVE rule approved before rules were scoped: it carries the origin but runs everywhere.
    pool.exec_("UPDATE pending_rules SET deploy_scope = 'global' WHERE rule_id = %s", (rid,))
    assert client.get(f"/api/ml-rules/{rid}", headers=h["owner"]).json()["can_revoke"] is False
    r = client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["owner"])
    assert r.status_code == 403 and "every origin" in r.json()["detail"]
    assert client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["admin"]).status_code == 200
    assert not (rules_dir / f"ml-{deployed}.conf").exists()


def test_a_revoked_rule_frees_the_origin_cap_but_not_its_id(client, team, service, monkeypatch):
    a, _b, h = team
    monkeypatch.setattr(ml_rule_service_module, "MAX_APPROVED_RULES_PER_ORIGIN", 1)
    first, first_id = _approved(client, h, service, a, key="k1", who="owner")
    assert client.post(f"/api/ml-rules/{first}/revoke", json={}, headers=h["owner"]).status_code == 200
    _second, second_id = _approved(client, h, service, a, key="k2", who="owner")
    assert second_id > first_id


def test_when_nginx_refuses_the_removal_the_rule_stays_approved(client, team, service, rules_dir, monkeypatch):
    a, _b, h = team
    rid, deployed = _approved(client, h, service, a)
    rm = ml_rule_service_module.RuleManager()

    def refuse():
        raise RuntimeError("nginx -t failed")
    monkeypatch.setattr(rm, "test_nginx", refuse)
    service.rule_manager = rm
    r = client.post(f"/api/ml-rules/{rid}/revoke", json={}, headers=h["owner"])
    assert r.status_code == 500
    assert (rules_dir / f"ml-{deployed}.conf").exists()
    row = service.get_rule_detail(rid)
    assert row["status"] == "approved" and "revoked_by" not in row
    actions = [e["action"] for e in audit_log.get_audit_log(a, db=audit_log.db) if e["action"].startswith("rule.revoke")]
    assert sorted(actions) == ["rule.revoke", "rule.revoke_failed"]


# ---- CVE scan of one origin (2026-10-27) -------------------------------------------------------

@pytest.fixture()
def cve_feed(monkeypatch):
    from unittest.mock import AsyncMock

    class _AllowAll:
        def is_allowed(self, *a, **k):
            return True, 1, 0

    monkeypatch.setattr(ml_rules_module, "_cve_scan_limiter", _AllowAll())
    cve = {"cve": {"id": "CVE-2026-7001", "descriptions": [{"lang": "en", "value": "nginx path bug"}],
                   "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*"}]}]}],
                   "metrics": {}}}
    monkeypatch.setattr(ml_rules_module, "fetch_recent_cves", AsyncMock(return_value=[cve]))
    monkeypatch.setattr(ml_rules_module.gemini_service, "draft_cve_rule_pattern", AsyncMock(return_value=r"/nginx-bug"))


def test_owner_scans_only_their_origin(client, team, service, db, cve_feed):
    a, b, h = team
    for oid in (a, b):
        db.update_origin(oid, {"tech_stack_tags": ["nginx"]})
    r = client.post(f"/api/ml-rules/cve-scan?origin_id={a}", headers=h["editor"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["origin_id"] == a and body["proposals_created"] == 1
    assert {p["origin_id"] for p in body["proposals"]} == {a}
    assert [r["origin_id"] for r in service.list_rules()] == [a]
    assert [e["action"] for e in audit_log.get_audit_log(a, db=audit_log.db)] == ["cve_scan.run"]


def test_who_may_scan_an_origin(client, team, service, db, cve_feed):
    a, b, h = team
    db.update_origin(a, {"tech_stack_tags": ["nginx"]})
    assert client.post(f"/api/ml-rules/cve-scan?origin_id={a}", headers=h["viewer"]).status_code == 403
    assert client.post(f"/api/ml-rules/cve-scan?origin_id={a}", headers=h["stranger"]).status_code == 404
    assert client.post(f"/api/ml-rules/cve-scan?origin_id={b}", headers=h["owner"]).status_code == 404
    assert client.post("/api/ml-rules/cve-scan", headers=h["owner"]).status_code == 403   # every origin: admin only
    r = client.post(f"/api/ml-rules/cve-scan?origin_id={b}", headers=h["other_owner"])
    assert r.status_code == 400 and "tech stack" in r.json()["detail"]
    assert service.list_rules() == []


def test_an_origin_scan_is_rate_limited(client, team, db, monkeypatch, cve_feed):
    a, _b, h = team
    db.update_origin(a, {"tech_stack_tags": ["nginx"]})

    class _Refuse:
        def is_allowed(self, key, limit, window, fail_open=True):
            assert key == f"cve-scan:{a}" and fail_open is False
            return False, 0, 1200

    monkeypatch.setattr(ml_rules_module, "_cve_scan_limiter", _Refuse())
    r = client.post(f"/api/ml-rules/cve-scan?origin_id={a}", headers=h["owner"])
    assert r.status_code == 429 and r.headers["Retry-After"] == "1200"


# ---- the scoped rule text ------------------------------------------------------------------

def test_scoping_keeps_operator_escapes_and_a_message_with_commas():
    rf = ('SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)union\\s+select \\"x" \\\n'
          '    "id:1000600,\\\n    phase:2,\\\n    deny,\\\n    status:403,\\\n    severity:CRITICAL,\\\n'
          "    log,\\\n    msg:'Blocked, really: it\\'s SQLi'\"")
    text = scope_ml_rule_to_origin(rf, 1000600, "abc-123")
    assert text.splitlines()[1] == ("    \"id:1000600,phase:2,deny,status:403,severity:CRITICAL,log,"
                                    "msg:'Blocked, really: it\\'s SQLi',tag:'ml-rule',tag:'origin:abc-123',chain\"")
    assert text.splitlines()[2] == '    SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)union\\s+select \\"x" "t:none"'


@pytest.mark.parametrize("origin_id", ["", "a b", 'x"', "x\nSecRuleEngine Off", "a" * 65])
def test_scoping_refuses_a_bad_origin_id(origin_id):
    with pytest.raises(ValueError):
        scope_ml_rule_to_origin(gen3_rule_text(1000601, "v_xss_libinjection"), 1000601, origin_id)


@pytest.mark.parametrize("extra", ["capture", "setvar:tx.x=1", "multiMatch"])
def test_scoping_refuses_an_action_it_does_not_know_where_to_put(extra):
    rule = f'SecRule ARGS "@rx x" "id:1000602,phase:2,deny,{extra},msg:\'m\'"'
    with pytest.raises(ValueError):
        scope_ml_rule_to_origin(rule, 1000602, "abc")


def test_scoping_runs_the_global_checks_first():
    with pytest.raises(ValueError):
        scope_ml_rule_to_origin('SecRule ARGS "@rx x" "id:1000603,phase:2,deny,ctl:ruleEngine=Off"', 1000603, "abc")
    with pytest.raises(ValueError):
        scope_ml_rule_to_origin('SecRule ARGS "@rx x" "id:1000604,phase:2,deny"', 1000603, "abc")
