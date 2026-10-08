"""F-033: the generated global-whitelist rule must use an id no other rule file
uses (a duplicate id makes `nginx -t` fail on Main and every edge).
F-034: the manual /api/rules/sync endpoint is disabled and never shells out."""
import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

import services.ip_rule_service as ip_rules
from api import rules as rules_api
from services.rbac import require_admin

REPO_RULES = Path(__file__).resolve().parents[3] / "modsecurity" / "custom-rules"


def _ids(text):
    return re.findall(r"\bid:(\d+)", text)


def test_generated_whitelist_rule_id_is_unique(tmp_path, monkeypatch):
    for name in ("BLOCKLIST_TXT", "WHITELIST_TXT", "BLOCKLIST_CONF", "WHITELIST_CONF"):
        monkeypatch.setattr(ip_rules, name, tmp_path / getattr(ip_rules, name).name)
    svc = ip_rules.IPRuleService()
    conn = svc._get_conn()
    conn.execute(
        "INSERT INTO ip_rules (ip, rule_type, created_at) VALUES (?, 'allow', 1), (?, 'block', 1)",
        ("203.0.113.5", "198.51.100.9"),
    )
    conn.commit()
    conn.close()
    svc._sync_files_from_db()

    generated = (tmp_path / ip_rules.WHITELIST_CONF.name).read_text() + (
        tmp_path / ip_rules.BLOCKLIST_CONF.name
    ).read_text()
    gen_ids = _ids(generated)
    assert "9100000" in gen_ids and "1000001" not in gen_ids

    existing = []
    for f in REPO_RULES.glob("*.conf"):
        if f.name.startswith(("custom-000000-global", "custom-000001-global")):
            continue
        existing += _ids(f.read_text(errors="ignore"))
    assert not set(gen_ids) & set(existing), set(gen_ids) & set(existing)


def test_manual_sync_endpoint_is_gone_and_never_runs_the_script(monkeypatch):
    import subprocess

    def _boom(*a, **k):
        raise AssertionError("sync script must not run")

    monkeypatch.setattr(subprocess, "run", _boom)
    app = FastAPI()
    app.include_router(rules_api.router)
    app.dependency_overrides[require_admin] = lambda: {"user_id": "a", "role": "admin"}
    r = TestClient(app).post("/api/rules/sync", headers={"Authorization": "Bearer x"})
    assert r.status_code == 410
