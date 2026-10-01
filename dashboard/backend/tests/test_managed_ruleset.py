"""services/managed_ruleset.py: the versioned central ruleset (source ->
publish -> per-origin host map) plus its API in api/managed_rules.py.
Pure functions first (load_source validation, publish/version bookkeeping,
hostmap generation), then the HTTP surface: an origin Admin reads status and
flips auto/manual, a Viewer can only read, and the catalog/publish-now
endpoints are platform-admin only."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import services.managed_ruleset as mr
import services.tenant_service as tenant_service_module
from api import auth as auth_module
from api import managed_rules as managed_rules_module
from api import origins as origins_module
from api import rules as rules_module
from services.rate_limiter import limiter

RULE_1 = 'SecRule REQUEST_URI "@contains /evil" "id:3000001,phase:1,deny,status:403,log,severity:CRITICAL,msg:\'evil path\',tag:\'managed-ruleset\'"'
RULE_2 = 'SecRule ARGS "@contains jndi:" "id:3000002,phase:2,deny,status:403,log,severity:CRITICAL,msg:\'log4shell\',tag:\'managed-ruleset\'"'


@pytest.fixture()
def source_dir(tmp_path):
    d = tmp_path / "managed-rules"
    d.mkdir()
    (d / "001-rules.conf").write_text(RULE_1 + "\n" + RULE_2 + "\n", encoding="utf-8")
    return d


@pytest.fixture()
def catalog_path(tmp_path):
    return tmp_path / "data" / "managed_ruleset.json"


# ------------------------------------------------------------------- source


def test_load_source_rejects_forbidden_directive(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "bad.conf").write_text('SecRule REQUEST_URI "@rx x" "id:3000001,phase:1,deny,ctl:ruleRemoveById=1"\n', encoding="utf-8")
    with pytest.raises(mr.ManagedRulesetError, match="forbidden"):
        mr.load_source(d)


def test_load_source_rejects_id_outside_range(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "bad.conf").write_text('SecRule REQUEST_URI "@rx x" "id:1,phase:1,deny"\n', encoding="utf-8")
    with pytest.raises(mr.ManagedRulesetError, match="outside"):
        mr.load_source(d)


def test_load_source_rejects_duplicate_id(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "bad.conf").write_text(RULE_1 + "\n" + RULE_1.replace("evil path", "dup") + "\n", encoding="utf-8")
    with pytest.raises(mr.ManagedRulesetError, match="duplicate"):
        mr.load_source(d)


def test_load_source_ok(source_dir):
    rules = mr.load_source(source_dir)
    assert set(rules) == {3000001, 3000002}


# ------------------------------------------------------------------ publish


def test_publish_records_a_new_version_and_added_ids(source_dir, catalog_path):
    entry = mr.publish(source_dir, catalog_path)
    assert entry["version"] == 1
    assert entry["added"] == [3000001, 3000002]
    catalog = mr.load_catalog(catalog_path)
    assert mr.latest_version(catalog) == 1
    assert mr.rules_for_version(catalog, 1) == [3000001, 3000002]


def test_publish_with_unchanged_source_returns_none(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    assert mr.publish(source_dir, catalog_path) is None


def test_publish_a_retired_rule_stays_in_the_catalog_but_leaves_active_set(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    (source_dir / "001-rules.conf").write_text(RULE_1 + "\n", encoding="utf-8")  # drop rule 2
    entry = mr.publish(source_dir, catalog_path)
    assert entry["retired"] == [3000002]
    catalog = mr.load_catalog(catalog_path)
    assert mr.rules_for_version(catalog, 2) == [3000001]
    assert mr.rules_for_version(catalog, 1) == [3000001, 3000002]  # v1 pins still see the retired rule


def test_publish_refuses_to_change_a_published_rule(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    (source_dir / "001-rules.conf").write_text(
        RULE_1.replace("evil path", "changed") + "\n" + RULE_2 + "\n", encoding="utf-8"
    )
    with pytest.raises(mr.ManagedRulesetError, match="immutable"):
        mr.publish(source_dir, catalog_path)


def test_publish_refuses_to_reuse_a_retired_id(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    (source_dir / "001-rules.conf").write_text(RULE_1 + "\n", encoding="utf-8")
    mr.publish(source_dir, catalog_path)  # retires 3000002
    (source_dir / "001-rules.conf").write_text(RULE_1 + "\n" + RULE_2 + "\n", encoding="utf-8")
    with pytest.raises(mr.ManagedRulesetError, match="retired"):
        mr.publish(source_dir, catalog_path)


# --------------------------------------------------------------- host map


def test_render_hostmap_scopes_each_origin_to_its_own_hosts(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    catalog = mr.load_catalog(catalog_path)
    origins = [{"id": "o1"}, {"id": "o2"}]
    hosts = {"o1": ["a.example.com"], "o2": ["b.example.com"]}
    text = mr.render_hostmap(origins, hosts, catalog)
    # host_regex uses re.escape(), so the literal dot is backslash-escaped
    # in the generated rule -- assert on that, not the unescaped hostname.
    assert r"a\.example\.com" in text
    assert r"b\.example\.com" in text
    assert text.count("setvar:tx.waf_origin_id=o1") == 1
    assert text.count("setvar:tx.waf_origin_id=o2") == 1
    assert "&TX:waf_origin_id" in text  # fallback for unmapped hosts


def test_render_hostmap_skips_an_origin_with_no_verified_hosts(source_dir, catalog_path):
    catalog = mr.load_catalog(catalog_path)
    text = mr.render_hostmap([{"id": "o1"}], {}, catalog)
    assert "waf_origin_id=o1" not in text


def test_effective_version_manual_pin_is_clamped_to_latest(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    catalog = mr.load_catalog(catalog_path)
    latest = mr.latest_version(catalog)
    origin = {"managed_ruleset_mode": "manual", "managed_ruleset_version": latest + 50}
    assert mr.effective_version(origin, catalog) == latest


def test_effective_version_auto_always_tracks_latest(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    catalog = mr.load_catalog(catalog_path)
    origin = {"managed_ruleset_mode": "auto"}
    assert mr.effective_version(origin, catalog) == mr.latest_version(catalog)


def test_verified_hosts_by_origin_excludes_unverified_domains(db):
    db.origins_table.put_item(Item={"id": "o1", "status": "active"})
    db.domains_table.put_item(Item={"id": "d1", "origin_id": "o1", "domain_name": "unverified.example.com", "dns_verified": False})
    db.domains_table.put_item(Item={"id": "d2", "origin_id": "o1", "domain_name": "verified.example.com", "dns_verified": True})
    origins, by_origin = mr.verified_hosts_by_origin(db)
    assert by_origin.get("o1") == ["verified.example.com"]


def test_verified_hosts_by_origin_drops_a_host_claimed_by_two_origins(db):
    db.origins_table.put_item(Item={"id": "o1", "status": "active"})
    db.origins_table.put_item(Item={"id": "o2", "status": "active"})
    db.domains_table.put_item(Item={"id": "d1", "origin_id": "o1", "domain_name": "shared.example.com", "dns_verified": True})
    db.domains_table.put_item(Item={"id": "d2", "origin_id": "o2", "domain_name": "shared.example.com", "dns_verified": True})
    _origins, by_origin = mr.verified_hosts_by_origin(db)
    assert "shared.example.com" not in by_origin.get("o1", [])
    assert "shared.example.com" not in by_origin.get("o2", [])


def test_status_for_origin_shape(source_dir, catalog_path):
    mr.publish(source_dir, catalog_path)
    catalog = mr.load_catalog(catalog_path)
    status = mr.status_for_origin({"managed_ruleset_mode": "auto"}, catalog)
    assert status["mode"] == "auto"
    assert status["update_available"] is False
    assert len(status["rules"]) == 2
    assert all(r["active"] for r in status["rules"])


# ------------------------------------------------------------------- apply


def test_apply_rolls_back_on_a_failed_nginx_test(source_dir, catalog_path, tmp_path, db):
    mr.publish(source_dir, catalog_path)

    class _FailingRM:
        rules_dir = str(tmp_path / "rules")

        def test_nginx(self):
            raise RuntimeError("nginx -t failed")

        def reload_nginx(self):
            pass

    (tmp_path / "rules").mkdir()
    with pytest.raises(RuntimeError):
        mr.apply(_FailingRM(), db, catalog_path)
    assert not (tmp_path / "rules" / mr.RULES_FILE).exists()


# --------------------------------------------------------------------- HTTP


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    for module in (auth_module, origins_module, rules_module, managed_rules_module):
        test_app.include_router(module.router)
    return test_app


@pytest.fixture(autouse=True)
def _isolate_managed_ruleset_paths(monkeypatch, source_dir, catalog_path):
    """Every managed_rules.py endpoint calls mr.load_catalog()/publish()/
    apply() with their default (module-constant) paths -- point those at
    this test's throwaway source/catalog instead of the real
    modsecurity/managed-rules/ and dashboard/backend/data/managed_ruleset.json."""
    monkeypatch.setattr(mr, "SOURCE_DIR", source_dir)
    monkeypatch.setattr(mr, "CATALOG_PATH", catalog_path)
    monkeypatch.setattr(managed_rules_module.mr, "SOURCE_DIR", source_dir)
    monkeypatch.setattr(managed_rules_module.mr, "CATALOG_PATH", catalog_path)


@pytest.fixture()
def accounts(client: TestClient, register_user, auth_header):
    admin = register_user(email="mr-admin@example.com", username="mr_admin")  # platform admin (first user)
    origin_admin = register_user(email="mr-origin-admin@example.com", username="mr_origin_admin", role="viewer")
    viewer = register_user(email="mr-viewer@example.com", username="mr_viewer", role="viewer")
    admin_h = auth_header(admin["access_token"])
    origin_admin_h = auth_header(origin_admin["access_token"])
    viewer_h = auth_header(viewer["access_token"])

    origin_id = client.post("/api/origins", json={"label": "MR Origin", "ip": "203.0.113.70", "port": 80}, headers=origin_admin_h).json()["id"]
    tenant_service_module.invalidate_tenant_cache()
    resp = client.post(f"/api/origins/{origin_id}/viewers", json={"email": "mr-viewer@example.com"}, headers=origin_admin_h)
    assert resp.status_code == 200, resp.text
    return origin_id, admin_h, origin_admin_h, viewer_h


def test_origin_status_reflects_published_rules(client, accounts):
    origin_id, admin_h, origin_admin_h, _viewer_h = accounts
    client.post("/api/managed-rules/publish", headers=admin_h)
    status = client.get(f"/api/managed-rules/origins/{origin_id}/status", headers=origin_admin_h)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["mode"] == "auto"
    assert body["latest_version"] == 1
    assert len(body["rules"]) == 2


def test_viewer_can_read_status_but_not_change_mode(client, accounts):
    origin_id, _admin_h, _origin_admin_h, viewer_h = accounts
    assert client.get(f"/api/managed-rules/origins/{origin_id}/status", headers=viewer_h).status_code == 200
    resp = client.put(f"/api/managed-rules/origins/{origin_id}/mode", json={"mode": "manual", "version": 0}, headers=viewer_h)
    assert resp.status_code == 403


def test_origin_admin_can_pin_to_manual_then_update_to_latest(client, accounts):
    origin_id, admin_h, origin_admin_h, _viewer_h = accounts
    client.post("/api/managed-rules/publish", headers=admin_h)

    pinned = client.put(f"/api/managed-rules/origins/{origin_id}/mode", json={"mode": "manual", "version": 0}, headers=origin_admin_h)
    assert pinned.status_code == 200, pinned.text
    assert pinned.json()["mode"] == "manual"
    assert pinned.json()["current_version"] == 0
    assert pinned.json()["update_available"] is True

    updated = client.post(f"/api/managed-rules/origins/{origin_id}/update", headers=origin_admin_h)
    assert updated.status_code == 200, updated.text
    assert updated.json()["current_version"] == 1
    assert updated.json()["update_available"] is False


def test_catalog_and_publish_are_platform_admin_only(client, accounts):
    _origin_id, admin_h, origin_admin_h, viewer_h = accounts
    assert client.get("/api/managed-rules/catalog", headers=origin_admin_h).status_code == 403
    assert client.get("/api/managed-rules/catalog", headers=viewer_h).status_code == 403
    assert client.get("/api/managed-rules/catalog", headers=admin_h).status_code == 200
    assert client.post("/api/managed-rules/publish", headers=origin_admin_h).status_code == 403

    first = client.post("/api/managed-rules/publish", headers=admin_h)
    assert first.status_code == 200 and first.json()["published"] is True
    second = client.post("/api/managed-rules/publish", headers=admin_h)
    assert second.status_code == 200 and second.json()["published"] is False


# --- the real source in modsecurity/managed-rules -------------------------

import re  # noqa: E402
import urllib.parse  # noqa: E402
from pathlib import Path  # noqa: E402

REPO_SOURCE = Path(__file__).resolve().parents[3] / "modsecurity" / "managed-rules"


def _rule_regex(rule_text: str) -> "re.Pattern":
    """The @rx operand as libmodsecurity reads it: only \\" is unescaped."""
    operand = re.search(r'"@rx (.*?)(?<!\\)"', rule_text).group(1).replace('\\"', '"')
    return re.compile(operand)


def test_repo_managed_rules_load():
    rules = mr.load_source(REPO_SOURCE)
    assert {3000001, 3000002, 3000003, 3000004, 3000005, 3000006} <= set(rules)


def test_path_sqli_rule_blocks_quote_then_sql_but_not_apostrophes_in_words():
    rx = _rule_regex(mr.load_source(REPO_SOURCE)[3000006])

    def hit(path):  # t:urlDecodeUni,t:lowercase
        return bool(rx.search(urllib.parse.unquote(path).lower()))

    for attack in ("/products/1'%20OR%201=1--", "/products/1' or '1'='1", "/item/5%22%20UNION%20SELECT%201",
                   "/a/1';drop", "/a/1')%20or%20(1", "/a/x'--", "/a/1' order by 3"):
        assert hit(attack), attack
    for benign in ("/blog/don't-stop", "/authors/o'reilly", "/music/rock'n'roll", "/", "/api/items/42",
                   "/search/shoes", "/products/1", "/docs/the-or-operator"):
        assert not hit(benign), benign
