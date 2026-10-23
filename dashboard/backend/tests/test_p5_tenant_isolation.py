"""Phase 5: what a non-admin can see.

C3/H46  postmortems carry system-wide audit events only for platform admins.
H22     telegram_chat_id is admin-only in GET /api/settings.
H24     /api/system/status gives viewers up/down only.
H26     settings that do nothing are reported as not implemented.
"""
import uuid
from datetime import datetime, timedelta, timezone

import api.ai_summary as ai
from services import audit_log
from services.settings_service import NOT_IMPLEMENTED_SETTINGS, mask_settings


def _users(register_user, auth_header):
    tag = uuid.uuid4().hex[:6]
    admin = register_user(f"p5a-{tag}@example.com", f"p5a{tag}")
    tenant = register_user(f"p5t-{tag}@example.com", f"p5t{tag}")
    return admin, tenant


def _origin(client, h, ip="203.0.113.150"):
    r = client.post("/api/origins", json={"label": "p5-site", "ip": ip, "port": 8080}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _window():
    now = datetime.now(timezone.utc)
    return {"start_time": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")}


def test_tenant_postmortem_has_no_global_events(client, register_user, auth_header, monkeypatch):
    _, tenant = _users(register_user, auth_header)
    th = auth_header(tenant["access_token"])
    oid = _origin(client, th)
    audit_log.write_audit_event(scope_id="global", actor_user_id=None, actor_username="ops",
                                action="settings.update", summary="secret system change", details={})
    async def no_ai(_):
        return {"narrative": None, "degraded": True}
    monkeypatch.setattr(ai.gemini_service, "generate_postmortem_narrative", no_ai)
    r = client.post(f"/api/ai/postmortems/{oid}", json=_window(), headers=th)
    assert r.status_code == 200, r.text
    events = r.json()["postmortem"]["audit_events"]
    assert all(e.get("scope") != "global" for e in events)
    assert not any("secret system change" in str(e) for e in events)


def test_admin_report_is_redacted_for_origin_viewers():
    item = {"origin_id": "o", "ai_narrative": "mentions the system change",
            "audit_events": [{"scope": "origin", "action": "origin.update"},
                             {"scope": "global", "action": "settings.update"}]}
    viewer = ai._redact_for(item, {"role": "viewer"})
    assert [e["scope"] for e in viewer["audit_events"]] == ["origin"]
    assert viewer["ai_narrative"] is None and viewer["ai_narrative_hidden"] is True
    assert ai._redact_for(item, {"role": "admin"}) is item


def test_unwired_settings_are_reported():
    out = mask_settings({"real_ip_header": "X-Real-IP"})
    assert set(out["not_implemented"]) == set(NOT_IMPLEMENTED_SETTINGS)


def _status(monkeypatch, role):
    import asyncio
    import main
    import api.cdn as cdn_api
    monkeypatch.setattr(main, "_port_open", lambda port: True)
    monkeypatch.setattr(main, "_db_ping", lambda: (_ for _ in ()).throw(RuntimeError("password authentication failed for user x")))
    async def nodes(current_user=None):
        return []
    monkeypatch.setattr(cdn_api, "cdn_nodes", nodes)
    return asyncio.run(main.system_status(current_user={"role": role, "user_id": "u"}))


def test_system_status_for_viewers_has_no_internals(monkeypatch):
    out = _status(monkeypatch, "viewer")
    assert "system" not in out
    assert all("port" not in s for s in out["services"].values())
    assert out["db"]["detail"] == ""


def test_system_status_for_admins_is_complete(monkeypatch):
    out = _status(monkeypatch, "admin")
    assert "load_average" in out["system"]
    assert all("port" in s for s in out["services"].values())
    assert "password authentication failed" in out["db"]["detail"]


# ---- P5.4 H25/H34: alert recipients follow role changes at once
def test_demoted_admin_leaves_alert_recipients_at_once(register_user):
    from services import telegram_listener as tl
    from services.auth_service import AuthService
    svc = AuthService()
    tag = uuid.uuid4().hex[:6]
    u = register_user(f"p5r-{tag}@example.com", f"p5r{tag}")["user"]
    svc.update_user_role(u["user_id"], "admin")
    svc.set_telegram_chat_id(u["user_id"], "424242")
    tl.invalidate_user_cache()
    assert any(r["user_id"] == u["user_id"] and r["role"] == "admin" for r in tl._get_telegram_users())
    svc.update_user_role(u["user_id"], "viewer")
    assert all(r["role"] == "viewer" for r in tl._get_telegram_users() if r["user_id"] == u["user_id"])


def test_role_change_by_another_process_is_noticed(register_user):
    # Another process (e.g. the log analyzer) changes the role: no in-process
    # invalidation happens, the fingerprint must still force a refresh.
    from services import telegram_listener as tl
    from services.auth_service import AuthService
    svc = AuthService()
    tag = uuid.uuid4().hex[:6]
    u = register_user(f"p5x-{tag}@example.com", f"p5x{tag}")["user"]
    svc.update_user_role(u["user_id"], "admin")
    svc.set_telegram_chat_id(u["user_id"], "434343")
    tl.invalidate_user_cache()
    tl._get_telegram_users()
    svc._pg.set_field(u["user_id"], "role", "viewer")   # bypasses invalidate_user_cache
    svc._pg.bump_token_version(u["user_id"])            # what any role change does
    assert all(r["role"] == "viewer" for r in tl._get_telegram_users() if r["user_id"] == u["user_id"])


# ---- P5.4 H33/H43: restoring counts against the owner's quota
def test_restore_is_owner_only_and_checks_the_owners_quota(client, register_user, auth_header, monkeypatch):
    import services.origin_service as os_mod
    monkeypatch.setattr(os_mod, "ORIGINS_QUOTA_DEFAULT", 1)
    tag = uuid.uuid4().hex[:6]
    owner = register_user(f"p5o-{tag}@example.com", f"p5o{tag}")
    editor = register_user(f"p5e-{tag}@example.com", f"p5e{tag}")
    oh, eh = auth_header(owner["access_token"]), auth_header(editor["access_token"])
    first = _origin(client, oh, ip="203.0.113.151")
    assert client.post(f"/api/origins/{first}/editors", json={"email": editor["user"]["email"]}, headers=oh).status_code == 200
    assert client.delete(f"/api/origins/{first}", headers=oh).status_code == 200      # archive
    _origin(client, oh, ip="203.0.113.152")                                          # owner now at limit
    assert client.post(f"/api/origins/{first}/restore", headers=eh).status_code == 403  # editors never restore
    r = client.post(f"/api/origins/{first}/restore", headers=oh)
    assert r.status_code == 400 and "quota" in r.text.lower()


# ---- P5.5 H47/H48: input bounds
def test_status_filter_accepts_only_ascii_status_codes():
    from services.clickhouse_service import status_code_filter
    assert status_code_filter("403") == 403
    for bad in ("²", "٤٠٣", "4033", "40", "abc", "", None, "999", "0403"):
        assert status_code_filter(bad) is None, bad


def test_logs_api_rejects_malformed_status_with_422(client, register_user, auth_header):
    # Plan P5.5: a malformed status filter is a 422, not a 500 and not a
    # silently dropped filter.
    from fastapi.testclient import TestClient
    import main
    tag = uuid.uuid4().hex[:6]
    h = auth_header(register_user(f"p5s-{tag}@example.com", f"p5s{tag}")["access_token"])
    c = TestClient(main.app)
    for path in ("/api/logs", "/api/logs/stream", "/api/logs/histogram"):
        for bad in ("²⁰⁰", "٤٠٣", "4033", "40", "abc", "0403", "999"):
            r = c.get(path, params={"status": bad}, headers=h)
            assert r.status_code == 422, (path, bad, r.status_code)
        for good in ("ALL", "BLOCKED", "ALLOWED", "403"):
            r = c.get(path, params={"status": good}, headers=h)
            assert r.status_code != 422, (path, good, r.text)


def test_cdn_logs_limit_is_bounded(client, register_user, auth_header):
    from fastapi.testclient import TestClient
    import main
    tag = uuid.uuid4().hex[:6]
    h = auth_header(register_user(f"p5l-{tag}@example.com", f"p5l{tag}")["access_token"])
    c = TestClient(main.app)
    assert c.get("/api/cdn/logs?limit=1000000", headers=h).status_code == 422
    assert c.get("/api/cdn/logs?limit=0", headers=h).status_code == 422


# ---- P5.6 N19: the deliberately vulnerable DVWA app no longer runs on Main
def test_dvwa_is_not_on_mains_network():
    from pathlib import Path
    import yaml
    repo = Path(__file__).resolve().parents[3]
    services = yaml.safe_load((repo / "docker-compose.yml").read_text())["services"]
    assert "dvwa" not in services
    assert "dvwa" not in (services["waf"].get("depends_on") or [])
    tpl = (repo / "nginx/templates/conf.d/default.conf.template").read_text()
    assert "server dvwa:80" not in tpl and "dvwa_backend" not in tpl


# ---- P5.7 H50: the approval queue shows who asked for a proposal
def test_requested_proposal_names_the_requester_and_merged_hits_too():
    from services.ml_rule_service import MLRuleService
    svc = MLRuleService()
    key = f"p5-dedup-{uuid.uuid4().hex[:8]}"
    base = {"pattern": "@rx union.select", "secrule_template": 'SecRule ARGS "@rx union.select" "id:{RULE_ID},phase:2,deny"',
            "source_url": "/p?id=1 union select", "dedup_key": key}
    rule = svc.create_pending_rule({**base, "requested_by": "viewer-a", "requested_by_id": "u-a"})
    assert rule["examples"][0]["requested_by"] == "viewer-a"
    merged = svc.record_hit(svc.find_pending_by_dedup_key(key), {**base, "requested_by": "viewer-b", "requested_by_id": "u-b"})
    assert [e.get("requested_by") for e in merged["examples"]][:2] == ["viewer-b", "viewer-a"]


def test_automatic_proposal_has_no_requester():
    from services.ml_rule_service import MLRuleService
    rule = MLRuleService().create_pending_rule({"pattern": "@rx x", "source_url": "/x",
                                                "dedup_key": f"p5-auto-{uuid.uuid4().hex[:8]}"})
    assert "requested_by" not in rule["examples"][0]
