"""A site's own IP access list and rate limits (api/site_access.py,
services/origin_ip_rules.py, migration 0015), and the platform-wide lists
becoming the operator's only (2026-10-25)."""
from pathlib import Path

import fakeredis
import pytest

from api import rules as rules_module
from api import site_access
from db import pool
from services import audit_log, origin_ip_rules, site_alerts, tenant_service


@pytest.fixture(autouse=True)
def _platform_routers(client):
    from api import ip_rules as ip_rules_module
    from api import rate_limits as rate_limits_module
    client.app.include_router(ip_rules_module.router)
    client.app.include_router(rate_limits_module.router)


@pytest.fixture()
def redis_(monkeypatch):
    r = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(site_access.rate_service, "redis_client", r)
    from api import rate_limits as rate_limits_module
    monkeypatch.setattr(rate_limits_module.service, "redis_client", r)
    return r


@pytest.fixture()
def team(client, register_user, auth_header):
    support = register_user(email="sa-support@example.com", username="sa_support")  # first account = operator
    owner = register_user(email="sa-owner@example.com", username="sa_owner")
    editor = register_user(email="sa-editor@example.com", username="sa_editor")
    viewer = register_user(email="sa-viewer@example.com", username="sa_viewer")
    stranger = register_user(email="sa-stranger@example.com", username="sa_stranger")
    h = {k: auth_header(u["access_token"]) for k, u in
         (("support", support), ("owner", owner), ("editor", editor), ("viewer", viewer), ("stranger", stranger))}
    oid = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.70", "port": 80}, headers=h["owner"]).json()["id"]
    for u, role in ((editor, "editor"), (viewer, "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)", (oid, u["user"]["user_id"], role))
    tenant_service._TENANT_CACHE.clear()
    return oid, h


def _site_file(oid) -> Path:
    return Path(rules_module.rule_manager.rules_dir) / f"siteip-{oid}.conf"


# ---- IP access --------------------------------------------------------------

def test_owner_and_editor_manage_the_sites_ip_list(client, team):
    oid, h = team
    r = client.post(f"/api/origins/{oid}/ip-rules", json={"ip": "198.51.100.7", "action": "block", "note": "scanner"}, headers=h["owner"])
    assert r.status_code == 200, r.text
    r2 = client.post(f"/api/origins/{oid}/ip-rules", json={"ip": "192.0.2.0/24", "action": "allow", "hours": 2}, headers=h["editor"])
    assert r2.status_code == 200, r2.text
    assert r2.json()["rule"]["expires_at"]

    listed = client.get(f"/api/origins/{oid}/ip-rules", headers=h["viewer"]).json()["rules"]
    assert {(x["ip"], x["action"]) for x in listed} == {("198.51.100.7", "block"), ("192.0.2.0/24", "allow")}

    text = _site_file(oid).read_text()
    assert f'SecRule TX:waf_origin_id "@streq {oid}"' in text
    assert '"@ipMatch 198.51.100.7"' in text and '"@ipMatch 192.0.2.0/24"' in text
    assert text.index("deny,status:403") < text.index("allow,nolog")  # block is checked first

    rid = r.json()["rule"]["id"]
    assert client.delete(f"/api/origins/{oid}/ip-rules/{rid}", headers=h["owner"]).status_code == 200
    assert "198.51.100.7" not in _site_file(oid).read_text()


def test_viewers_read_and_strangers_see_nothing(client, team):
    oid, h = team
    body = {"ip": "198.51.100.8", "action": "block"}
    assert client.post(f"/api/origins/{oid}/ip-rules", json=body, headers=h["viewer"]).status_code == 403
    assert client.post(f"/api/origins/{oid}/ip-rules", json=body, headers=h["stranger"]).status_code in (403, 404)
    assert client.get(f"/api/origins/{oid}/ip-rules", headers=h["stranger"]).status_code in (403, 404)


@pytest.mark.parametrize("ip, why", [("not-an-ip", "not an IP"), ("10.0.0.0/8", "too broad"), ("2001:db8::/16", "too broad")])
def test_bad_or_too_broad_entries_are_refused(client, team, ip, why):
    oid, h = team
    r = client.post(f"/api/origins/{oid}/ip-rules", json={"ip": ip, "action": "block"}, headers=h["owner"])
    assert r.status_code == 422 and why in r.json()["detail"]


def test_an_ip_is_listed_once_and_the_last_rule_removes_the_file(client, team):
    oid, h = team
    body = {"ip": "198.51.100.9", "action": "block"}
    rid = client.post(f"/api/origins/{oid}/ip-rules", json=body, headers=h["owner"]).json()["rule"]["id"]
    again = client.post(f"/api/origins/{oid}/ip-rules", json=body, headers=h["owner"])
    assert again.status_code == 422 and "already" in again.json()["detail"]
    client.delete(f"/api/origins/{oid}/ip-rules/{rid}", headers=h["owner"])
    assert not _site_file(oid).exists()


def test_expired_rules_leave_the_file(client, team):
    oid, h = team
    client.post(f"/api/origins/{oid}/ip-rules", json={"ip": "198.51.100.10", "action": "block", "hours": 1}, headers=h["owner"])
    client.post(f"/api/origins/{oid}/ip-rules", json={"ip": "198.51.100.11", "action": "block"}, headers=h["owner"])
    pool.exec_("UPDATE origin_ip_rules SET expires_at = now() - interval '1 minute' WHERE ip = '198.51.100.10'")
    assert site_access.ip_service.expire() == 1
    text = _site_file(oid).read_text()
    assert "198.51.100.10" not in text and "198.51.100.11" in text


def test_changes_are_audited_and_reach_the_owner(client, team):
    oid, h = team
    client.post(f"/api/origins/{oid}/ip-rules", json={"ip": "198.51.100.12", "action": "block"}, headers=h["editor"])
    events = audit_log.get_audit_log(oid, db=audit_log.db)
    assert [e["action"] for e in events if e["action"].startswith("site_ip_rule")] == ["site_ip_rule.add"]
    assert {"site_ip_rule.add", "site_rate_limit.add"} <= site_alerts.TEAM_ACTIONS


def test_render_uses_a_slot_per_site():
    text = origin_ip_rules.render("abc-1", 3, ["198.51.100.1"], [])
    assert "id:3500006," in text and "allow" not in text
    assert origin_ip_rules.render("abc-1", 3, [], []) is None


# ---- rate limits --------------------------------------------------------------

RATE = {"name": "Login guard", "path_pattern": "/login", "method": "POST", "limit_count": 5, "window_seconds": 60}


def test_a_site_has_its_own_rate_limits(client, team, redis_):
    oid, h = team
    r = client.post(f"/api/origins/{oid}/rate-limits", json=RATE, headers=h["owner"])
    assert r.status_code == 200, r.text
    rid = r.json()["rule"]["id"]
    assert [x["id"] for x in client.get(f"/api/origins/{oid}/rate-limits", headers=h["viewer"]).json()["rules"]] == [rid]
    # not in the platform list, but published to control-api with its site
    assert rid not in [x["id"] for x in client.get("/api/rate-limits/rules", headers=h["support"]).json()["rules"]]
    import json
    published = {x["id"]: x for x in json.loads(redis_.get("waf:ratelimit:rules"))}
    assert published[rid]["origin_id"] == oid

    up = client.put(f"/api/origins/{oid}/rate-limits/{rid}", json={"limit_count": 9, "enabled": False}, headers=h["editor"])
    assert up.status_code == 200 and up.json()["rule"]["limit_count"] == 9 and up.json()["rule"]["enabled"] == 0
    assert client.post(f"/api/origins/{oid}/rate-limits", json=RATE, headers=h["viewer"]).status_code == 403
    assert client.delete(f"/api/origins/{oid}/rate-limits/{rid}", headers=h["owner"]).status_code == 200
    assert client.get(f"/api/origins/{oid}/rate-limits", headers=h["owner"]).json()["rules"] == []


def test_a_site_cannot_touch_platform_or_other_sites_rules(client, team, redis_):
    oid, h = team
    assert client.put(f"/api/origins/{oid}/rate-limits/rule_auth_protect", json={"limit_count": 1}, headers=h["owner"]).status_code == 404
    assert client.delete(f"/api/origins/{oid}/rate-limits/rule_auth_protect", headers=h["owner"]).status_code == 404
    bad = client.post(f"/api/origins/{oid}/rate-limits", json={**RATE, "path_pattern": "login"}, headers=h["owner"])
    assert bad.status_code == 422


def test_platform_lists_are_the_operators_only(client, team, redis_):
    _oid, h = team
    for path in ("/api/ip-rules/", "/api/rate-limits/rules", "/api/rate-limits/throttled"):
        assert client.get(path, headers=h["owner"]).status_code == 403, path
        assert client.get(path, headers=h["support"]).status_code == 200, path


def test_throttled_clients_are_shown_to_the_sites_team_and_hidden_from_the_operator(client, team, redis_, monkeypatch):
    oid, h = team
    redis_.hset("waf:shield:hostmap", "shop.example.com", oid)
    redis_.set("rate:limit:rule_edge_flood:shop.example.com|198.51.100.20", 7, ex=30)
    redis_.set("rate:limit:rule_edge_flood:scan.target|198.51.100.21", 3, ex=30)
    site = client.get(f"/api/origins/{oid}/rate-limits/throttled", headers=h["viewer"]).json()["throttled_clients"]
    assert [c["ip"] for c in site] == ["198.51.100.20"]

    monkeypatch.setattr(tenant_service, "admin_log_scope", lambda: ({"shop.example.com"}, set(), {oid}, set()))
    body = client.get("/api/rate-limits/throttled", headers=h["support"]).json()
    assert [c["ip"] for c in body["throttled_clients"]] == ["198.51.100.21"]
    assert body["hidden_site_clients"] == 1
    monkeypatch.setattr(tenant_service, "admin_log_scope",
                        lambda: ({"shop.example.com"}, {"shop.example.com"}, {oid}, {oid}))  # support grant open
    body = client.get("/api/rate-limits/throttled", headers=h["support"]).json()
    assert sorted(c["ip"] for c in body["throttled_clients"]) == ["198.51.100.20", "198.51.100.21"]
