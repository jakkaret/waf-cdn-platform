"""Phase 4 (alerts, ML rules, threshold, audit, status, postmortems on
PostgreSQL): the guarantees the migration plan asks for. PostgreSQL-only
(DATA_BACKEND=postgres); the DynamoDB path keeps its old behaviour."""
import os
import threading
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.helpers.seed import seed_domain, seed_origin, uid

pytestmark = pytest.mark.skipif(os.environ.get("DATA_BACKEND", "").strip().lower() != "postgres",
                                reason="PostgreSQL-only guarantees (DATA_BACKEND=postgres)")


def _audit_rows(scope_id):
    from db import pool
    return pool.q("SELECT action, details FROM audit_logs WHERE scope_id = %s ORDER BY event_id", (scope_id,))


# ------------------------------------------------------------ fail-closed

def test_an_origin_edit_that_cannot_be_audited_does_not_happen(app, register_user, auth_header, monkeypatch):
    import services.audit_log as audit_log_module
    from services.pg_store import PgStore

    class _NoAudit(PgStore):
        def put_audit_event(self, item):
            raise RuntimeError("audit store down")

    owner = register_user(email="fc-owner@example.com", username="fc_owner")
    h = auth_header(owner["access_token"])
    client = TestClient(app, raise_server_exceptions=False)
    origin_id = client.post("/api/origins", json={"label": "before", "ip": "203.0.113.80", "port": 80},
                            headers=h).json()["id"]
    monkeypatch.setattr(audit_log_module, "db", _NoAudit())
    resp = client.put(f"/api/origins/{origin_id}", json={"label": "after"}, headers=h)
    assert resp.status_code >= 500
    from services.dynamodb_service import DynamoDBService
    assert DynamoDBService().get_origin_by_id(origin_id)["label"] == "before"   # rolled back


def test_settings_are_reverted_when_the_audit_cannot_be_written(monkeypatch, register_user, auth_header):
    import services.audit_log as audit_log_module
    from api import auth as auth_module
    from api import settings as settings_module
    from services.pg_store import PgStore

    class _NoAudit(PgStore):
        def put_audit_event(self, item):
            raise RuntimeError("audit store down")

    state = {"paranoia_level": 1}
    service = MagicMock()
    service.get_settings.side_effect = lambda: dict(state)
    service.update_settings.side_effect = lambda d: state.update(d) or dict(state)
    monkeypatch.setattr(settings_module, "service", service)
    monkeypatch.setattr(audit_log_module, "db", _NoAudit())
    app = FastAPI()
    app.include_router(auth_module.router)
    app.include_router(settings_module.router)
    client = TestClient(app, raise_server_exceptions=False)
    admin = client.post("/api/auth/register", json={"email": "set-a@example.com", "username": "set_a",
                                                   "password": "Sup3rSecret!"}).json()
    resp = client.post("/api/settings/", json={"paranoia_level": 3},
                       headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert resp.status_code == 500
    assert state["paranoia_level"] == 1          # the change was put back


# ------------------------------------------------------------- approve

@pytest.fixture()
def rules(monkeypatch):
    import services.ml_rule_service as ml_rule_service_module
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())
    service = ml_rule_service_module.MLRuleService()
    service.rule_manager.list_rules.return_value = []     # no files on disk
    return service


def _proposal(rules, n):
    return rules.create_pending_rule({"pattern": f"@rx x{n}", "secrule_template": 'SecRule ARGS "x" "id:{RULE_ID}"',
                                      "generator": "gen3-detector", "dedup_key": f"k{n}"})


def test_a_deleted_rule_file_never_lets_an_id_be_handed_out_twice(rules):
    a = rules.approve_rule(_proposal(rules, 1)["rule_id"], approved_by="admin")
    # DELETE /api/rules removes ml-<id>.conf without touching the row: the
    # disk no longer shows id A, the table still does.
    b = rules.approve_rule(_proposal(rules, 2)["rule_id"], approved_by="admin")
    assert b["deployed_rule_id"] > a["deployed_rule_id"] >= 1000500


def test_a_failed_deploy_puts_the_rule_back_to_pending_and_says_so(rules):
    import services.audit_log as audit_log_module
    rule_id = _proposal(rules, 3)["rule_id"]
    rules.rule_manager.write_ml_rule.side_effect = OSError("disk full")

    def _audit(action):
        return lambda r, *_: audit_log_module.write_audit_event(
            scope_id="global", actor_user_id=None, actor_username="admin", action=action,
            summary=action, details={"rule_id": rule_id})

    with pytest.raises(OSError):
        rules.approve_rule(rule_id, approved_by="admin", on_approved=_audit("rule.approve"),
                           on_deploy_failed=_audit("rule.approve_failed"))
    rule = rules.get_rule_detail(rule_id)
    assert rule["status"] == "pending" and "deployed_rule_id" not in rule
    actions = [r["action"] for r in _audit_rows("global") if r["details"].get("rule_id") == rule_id]
    assert actions == ["rule.approve", "rule.approve_failed"]


def test_two_concurrent_proposals_with_one_dedup_key_make_one_row(rules):
    barrier = threading.Barrier(2)

    def _go():
        barrier.wait()
        rules.create_pending_rule({"pattern": "@rx same", "generator": "gen3-detector", "dedup_key": "same-key"})

    threads = [threading.Thread(target=_go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = [r for r in rules.list_rules("pending") if r["dedup_key"] == "same-key"]
    assert len(rows) == 1 and rows[0]["hit_count"] == 2


# ------------------------------------------- no transaction around slow I/O

def test_cve_scan_holds_no_transaction_while_calling_nvd_and_gemini(app, register_user, auth_header, monkeypatch):
    from api import ml_rules as ml_rules_module
    from db import pool
    import services.ml_rule_service as ml_rule_service_module
    from tests.test_cve_auto_patch import _cve

    admin = register_user(email="cve-pg@example.com", username="cve_pg")   # first user = admin (test env)
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())
    monkeypatch.setattr(ml_rules_module, "rule_service", ml_rule_service_module.MLRuleService())
    seed_origin(ml_rules_module.rule_service.db, {"id": "cve-o", "label": "shop", "status": "active",
                                                  "tech_stack_tags": ["nginx"]})
    seen_open = []

    async def _fetch(*a, **k):
        seen_open.append(pool._current_conn.get() is not None)
        return [_cve(cve_id="CVE-2026-7777", vendor="nginx", product="nginx")]

    async def _draft(*a, **k):
        seen_open.append(pool._current_conn.get() is not None)
        return r"/nginx-exploit"

    monkeypatch.setattr(ml_rules_module, "fetch_recent_cves", AsyncMock(side_effect=_fetch))
    monkeypatch.setattr(ml_rules_module.gemini_service, "draft_cve_rule_pattern", AsyncMock(side_effect=_draft))
    app.include_router(ml_rules_module.router)
    client = TestClient(app)
    resp = client.post("/api/ml-rules/cve-scan", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200, resp.text
    assert resp.json()["proposals_created"] == 1
    assert seen_open and not any(seen_open)
    assert [r["action"] for r in _audit_rows("global")] == ["cve_scan.run"]


# ------------------------------------------------------------- shapes

def test_alert_shape_and_unattributed_alerts_stay_admin_only(app, register_user, auth_header):
    from api import ai_summary as ai_summary_module
    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    admin = register_user(email="al-admin@example.com", username="al_admin")
    viewer = register_user(email="al-viewer@example.com", username="al_viewer")
    client = TestClient(app)
    origin_id = client.post("/api/origins", json={"label": "al", "ip": "203.0.113.81", "port": 80},
                            headers=auth_header(viewer["access_token"])).json()["id"]
    seed_domain(db, {"origin_id": origin_id, "domain_name": "al-shop.example.org", "dns_verified": True})
    assert db.save_alert("x", "ALT-own", "1.2.3.4", "/a", "403", "m", domain="al-shop.example.org")
    assert db.save_alert("x", "ALT-none", "1.2.3.5", "/b", "403", "m", domain="nobody.example.org")
    alerts = {a["alert_id"]: a for a in db.get_all_alerts()}
    assert alerts["ALT-own"]["origin_id"] == origin_id
    assert alerts["ALT-none"]["origin_id"] == "unattributed"
    assert alerts["ALT-own"]["user_id"] == "default-user" and alerts["ALT-own"]["read"] is False
    assert alerts["ALT-own"]["timestamp"].endswith("Z")
    visible = ai_summary_module._visible_alerts_for_user({"user_id": viewer["user"]["user_id"], "role": "viewer"})
    assert [a["alert_id"] for a in visible] == ["ALT-own"]
    admin_view = ai_summary_module._visible_alerts_for_user({"user_id": admin["user"]["user_id"], "role": "admin"})
    assert {a["alert_id"] for a in admin_view} == {"ALT-own", "ALT-none"}


def test_audit_uptime_and_postmortem_shapes():
    import datetime as dt
    import services.audit_log as audit_log_module
    import services.public_status as public_status
    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    scope = uid("shape-origin")
    audit_log_module.write_audit_event(scope_id=scope, actor_user_id=None, actor_username="a",
                                       action="origin.update", summary="s", details={"k": 1}, db=db)
    [event] = audit_log_module.get_audit_log(scope, db=db)
    assert set(event) == {"scope_id", "event_id", "timestamp", "actor_user_id", "actor_username",
                          "action", "summary", "details"}
    assert isinstance(event["timestamp"], str) and dt.datetime.fromisoformat(event["timestamp"])
    assert event["actor_user_id"] == ""

    now = dt.datetime.now(dt.timezone.utc)
    public_status._record_history_sample([{"id": "th", "name": "TH", "status": "operational"}], db=db, now=now)
    history = public_status.get_uptime_history(days=2, db=db, now=now)
    assert history["th"][-1] == {"date": now.strftime("%Y-%m-%d"), "uptime_pct": 100.0}

    origin = seed_origin(db, {"id": "pm-origin", "label": "pm"})
    item = {"id": str(uuid.uuid4()), "origin_id": origin["id"], "origin_label": "pm", "created_by": None,
            "created_by_username": "", "created_at": now.isoformat(), "start_time": "2026-10-01 00:00:00",
            "end_time": "2026-10-01 06:00:00", "stats": {"requests": 1.5}, "hourly_buckets": [],
            "audit_events": [], "ai_narrative": None, "ai_narrative_degraded": False}
    db.save_postmortem(item)
    got = db.get_postmortem(item["id"])
    assert (got["start_time"], got["end_time"]) == ("2026-10-01 00:00:00", "2026-10-01 06:00:00")
    assert got["stats"] == {"requests": 1.5}
    assert [p["id"] for p in db.list_postmortems([origin["id"]])] == [item["id"]]
