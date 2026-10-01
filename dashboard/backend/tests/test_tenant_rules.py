"""services/tenant_rules.py: per-origin WAF rules, host-scoped via
tx.waf_origin_id (set by services/managed_ruleset.py's host map). Pure
validate()/render() coverage plus TenantRuleService against a throwaway
rules directory (no real nginx/docker involved -- test_nginx/reload_nginx
are no-op'd), then an HTTP slice proving an origin Admin can manage rules,
its Viewer can only read them, and a stranger origin sees neither."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import origins as origins_module
from api import rules as rules_module
from api import tenant_rules as tenant_rules_module
from services.rate_limiter import limiter
from services.tenant_rules import TenantRuleError, TenantRuleService, render, validate

# ------------------------------------------------------------------- pure


def test_validate_rejects_unknown_variable():
    with pytest.raises(TenantRuleError, match="variable"):
        validate({"variable": "TX", "operator": "@rx x", "message": "m"})


def test_validate_rejects_unknown_operator():
    with pytest.raises(TenantRuleError, match="operator"):
        validate({"variable": "REQUEST_URI", "operator": "@eval x", "message": "m"})


def test_validate_rejects_unsafe_regex():
    with pytest.raises(TenantRuleError, match="unsafe regex"):
        validate({"variable": "REQUEST_URI", "operator": "@rx (a+)+$", "message": "m"})


def test_validate_rejects_control_characters():
    with pytest.raises(TenantRuleError, match="control"):
        validate({"variable": "REQUEST_URI", "operator": "@contains x\ny", "message": "m"})


def test_validate_rejects_deceive_on_body_variable():
    with pytest.raises(TenantRuleError, match="DECEIVE"):
        validate({"variable": "REQUEST_BODY", "operator": "@contains x", "message": "m", "action": "DECEIVE"})


def test_validate_deceive_on_phase1_variable_ok():
    clean = validate({"variable": "REQUEST_URI", "operator": "@contains /admin", "message": "m", "action": "DECEIVE"})
    assert clean["action"] == "DECEIVE"


def test_render_scopes_rule_to_origin_and_never_touches_other_origins():
    clean = validate({"variable": "REQUEST_URI", "operator": "@contains /secret", "message": "block secret path"})
    text = render(2000001, "origin-a", clean)
    assert 'SecRule TX:waf_origin_id "@streq origin-a"' in text
    assert "chain" in text
    assert 'SecRule REQUEST_URI "@contains /secret"' in text
    assert "tag:'origin:origin-a'" in text


def test_render_disabled_rule_has_no_secrule():
    clean = validate({"variable": "REQUEST_URI", "operator": "@contains /x", "message": "m", "enabled": False})
    text = render(2000001, "origin-a", clean)
    assert "SecRule" not in text


def test_render_keeps_backslashes_untouched_in_a_regex():
    # libmodsecurity does not unescape `\\` inside an operator string, so
    # doubling backslashes (as the legacy escaper does) would turn \s into a
    # literal `\\s` that never matches. Checked against a real container.
    clean = validate({"variable": "ARGS", "operator": r"@rx (?i)union\s+select", "message": "m"})
    text = render(2000001, "origin-a", clean)
    assert r'"@rx (?i)union\s+select"' in text
    assert r"\\s" not in text.split("\n", 1)[1]


def test_validate_rejects_backslash_before_quote_or_at_end():
    for bad in ('@contains a\\"b', "@contains trailing\\"):
        with pytest.raises(TenantRuleError, match="backslash"):
            validate({"variable": "REQUEST_URI", "operator": bad, "message": "m"})


def test_chained_link_has_an_explicit_actions_string():
    # Without one, libmodsecurity swallows the next file's first line as the
    # action list and nginx -t fails for the whole WAF.
    text = render(2000001, "origin-a", validate({"variable": "REQUEST_URI", "operator": "@contains /x", "message": "m"}))
    assert text.rstrip("\n").endswith('"t:none"')


def test_render_escapes_a_quote_in_the_operator_value():
    clean = validate({"variable": "REQUEST_URI", "operator": '@contains "; drop', "message": "m"})
    text = render(2000001, "origin-a", clean)
    assert '\\"' in text.splitlines()[-1]


# --------------------------------------------------------------- service


@pytest.fixture()
def service(tmp_path):
    class _RM:
        rules_dir = str(tmp_path)

        def test_nginx(self):
            pass

        def reload_nginx(self):
            pass

    return TenantRuleService(_RM())


RULE = {"variable": "REQUEST_URI", "operator": "@contains /admin", "message": "block admin path"}


def test_create_then_list_is_scoped_per_origin(service):
    service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    service.create("origin-b", RULE, {"user_id": "u2", "username": "bob"})
    assert len(service.list(["origin-a"])) == 1
    assert len(service.list(["origin-a", "origin-b"])) == 2
    assert service.list(["origin-c"]) == []


def test_update_preserves_created_by(service):
    created = service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    updated = service.update("origin-a", created["id"], {**RULE, "message": "renamed"}, {"user_id": "u2", "username": "bob"})
    assert updated["message"] == "renamed"
    assert updated["created_by"] == "alice"
    assert updated["updated_by"] == "bob"


def test_delete_removes_the_rule(service):
    created = service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    service.delete("origin-a", created["id"])
    assert service.get("origin-a", created["id"]) is None


def test_delete_missing_rule_raises_keyerror(service):
    with pytest.raises(KeyError):
        service.delete("origin-a", 2999999)


def test_quota_is_enforced_per_origin(service, monkeypatch):
    monkeypatch.setattr("services.tenant_rules.MAX_RULES_PER_ORIGIN", 2)
    service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    with pytest.raises(TenantRuleError, match="at most"):
        service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})


def test_ids_never_collide_across_origins(service):
    a = service.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    b = service.create("origin-b", RULE, {"user_id": "u2", "username": "bob"})
    assert a["id"] != b["id"]


def test_a_failed_nginx_test_rolls_back_the_write(tmp_path):
    class _FailingRM:
        rules_dir = str(tmp_path)

        def test_nginx(self):
            raise RuntimeError("nginx -t failed")

        def reload_nginx(self):
            pass

    svc = TenantRuleService(_FailingRM())
    with pytest.raises(RuntimeError):
        svc.create("origin-a", RULE, {"user_id": "u1", "username": "alice"})
    assert svc.list(["origin-a"]) == []
    assert list(tmp_path.glob("tenant-*.conf")) == []


# ------------------------------------------------------------------- HTTP


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    for module in (auth_module, origins_module, rules_module, tenant_rules_module):
        test_app.include_router(module.router)
    return test_app


@pytest.fixture()
def accounts(client: TestClient, register_user, auth_header):
    admin = register_user(email="tr-admin@example.com", username="tr_admin")
    viewer = register_user(email="tr-viewer@example.com", username="tr_viewer", role="viewer")
    stranger = register_user(email="tr-stranger@example.com", username="tr_stranger", role="viewer")
    admin_h = auth_header(admin["access_token"])
    viewer_h = auth_header(viewer["access_token"])
    stranger_h = auth_header(stranger["access_token"])

    origin_id = client.post("/api/origins", json={"label": "TR Origin", "ip": "203.0.113.60", "port": 80}, headers=admin_h).json()["id"]
    tenant_service_module.invalidate_tenant_cache()
    resp = client.post(f"/api/origins/{origin_id}/viewers", json={"email": "tr-viewer@example.com"}, headers=admin_h)
    assert resp.status_code == 200, resp.text
    return origin_id, admin_h, viewer_h, stranger_h


def test_origin_admin_can_create_list_update_delete(client, accounts):
    origin_id, admin_h, _viewer_h, _stranger_h = accounts
    created = client.post(f"/api/origins/{origin_id}/waf-rules/", json=RULE, headers=admin_h)
    assert created.status_code == 200, created.text
    rid = created.json()["id"]

    listed = client.get(f"/api/origins/{origin_id}/waf-rules/", headers=admin_h)
    assert listed.status_code == 200
    assert [r["id"] for r in listed.json()["rules"]] == [rid]

    updated = client.put(f"/api/origins/{origin_id}/waf-rules/{rid}", json={**RULE, "message": "renamed"}, headers=admin_h)
    assert updated.status_code == 200
    assert updated.json()["message"] == "renamed"

    deleted = client.delete(f"/api/origins/{origin_id}/waf-rules/{rid}", headers=admin_h)
    assert deleted.status_code == 200
    assert client.get(f"/api/origins/{origin_id}/waf-rules/", headers=admin_h).json()["rules"] == []


def test_origin_viewer_can_read_but_not_write(client, accounts):
    origin_id, admin_h, viewer_h, _stranger_h = accounts
    created = client.post(f"/api/origins/{origin_id}/waf-rules/", json=RULE, headers=admin_h).json()

    assert client.get(f"/api/origins/{origin_id}/waf-rules/", headers=viewer_h).status_code == 200
    assert client.post(f"/api/origins/{origin_id}/waf-rules/", json=RULE, headers=viewer_h).status_code == 403
    assert client.put(f"/api/origins/{origin_id}/waf-rules/{created['id']}", json=RULE, headers=viewer_h).status_code == 403
    assert client.delete(f"/api/origins/{origin_id}/waf-rules/{created['id']}", headers=viewer_h).status_code == 403


def test_a_stranger_sees_nothing_for_this_origin(client, accounts):
    origin_id, _admin_h, _viewer_h, stranger_h = accounts
    assert client.get(f"/api/origins/{origin_id}/waf-rules/", headers=stranger_h).status_code == 403
    assert client.post(f"/api/origins/{origin_id}/waf-rules/", json=RULE, headers=stranger_h).status_code == 403
    assert client.get(f"/api/origins/{origin_id}/waf-rules/options", headers=stranger_h).status_code == 403


def test_origin_members_can_read_the_rule_builder_options(client, accounts):
    origin_id, admin_h, viewer_h, _stranger_h = accounts
    for h in (admin_h, viewer_h):
        resp = client.get(f"/api/origins/{origin_id}/waf-rules/options", headers=h)
        assert resp.status_code == 200
        assert "operators" in resp.json()


def test_invalid_rule_body_is_rejected_with_400(client, accounts):
    origin_id, admin_h, _viewer_h, _stranger_h = accounts
    resp = client.post(f"/api/origins/{origin_id}/waf-rules/", json={"variable": "TX", "operator": "@rx x", "message": "m"}, headers=admin_h)
    assert resp.status_code == 400
