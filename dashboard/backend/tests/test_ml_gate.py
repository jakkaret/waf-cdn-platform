"""Per-origin ML protection (services/ml_gate.py, api/ml_protection.py, the
/api/ml/gate relay, migration 0021).

What must hold: log mode is the default and never reaches the nginx map; a
malformed or missing policy never blocks; the bands decide exactly as
configured; only Owner/Editors change the setting, every change is audited;
the map holds only verified hosts of enforcing origins and is put back when
nginx refuses it; the relay fails open."""
import types
from typing import ClassVar

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import ml as ml_module
from api import ml_protection
from db import pool
from services import audit_log, ml_gate, ml_verdicts, tenant_service
from tests.helpers.seed import seed_domain


# ---- the decision -----------------------------------------------------------

@pytest.mark.parametrize("raw, want", [
    ("enforce:88:95", (88, 95)),
    ("enforce:0:95", (None, 95)),
    (" enforce:50:51 ", (50, 51)),
])
def test_valid_policies_parse(raw, want):
    assert ml_gate.parse_policy(raw) == want


@pytest.mark.parametrize("raw", [
    "", None, "log", "enforce", "enforce:95:88", "enforce:90:90", "enforce:49:95", "enforce:88:101",
    "enforce:88:50", "enforce:88:95;", "enforce:-1:95", "ENFORCE:88:95", "enforce:88:95:1",
])
def test_anything_else_never_enforces(raw):
    assert ml_gate.parse_policy(raw) is None


@pytest.mark.parametrize("score, want", [
    (0.0, "pass"), (0.8799, "pass"), (0.88, "challenge"), (0.9499, "challenge"), (0.95, "block"), (1.0, "block"),
])
def test_bands(score, want):
    assert ml_gate.decide(score, (88, 95)) == want


def test_without_a_challenge_band_only_block_or_pass():
    assert ml_gate.decide(0.94, (None, 95)) == "pass"
    assert ml_gate.decide(0.96, (None, 95)) == "block"


def test_policy_value_round_trips():
    for challenge, block in ((88, 95), (None, 99)):
        assert ml_gate.parse_policy(ml_gate.policy_value(challenge, block)) == (challenge, block)


# ---- the map ------------------------------------------------------------------

def test_map_lists_only_hosts_of_enforcing_origins():
    hostmap = {"b.example.com": "o1", "a.example.com": "o1", "log.example.com": "o2", "bad host;": "o1"}
    text = ml_gate.render_map(hostmap, {"o1": "enforce:88:95"})
    assert text.startswith(ml_gate.MAP_HEADER)
    assert ml_gate.hosts_in_map(text) == {"a.example.com": "enforce:88:95", "b.example.com": "enforce:88:95"}
    assert text.index("a.example.com") < text.index("b.example.com")  # stable bytes for the same input


def test_a_bad_policy_value_is_not_rendered():
    assert ml_gate.hosts_in_map(ml_gate.render_map({"a.example.com": "o1"}, {"o1": 'x"; default "enforce'})) == {}


class _Db:
    def __init__(self, rows):
        self.rows = rows

    def verified_hostnames_active(self):
        return self.rows


class _Rm:
    def __init__(self, fail=False):
        self.fail, self.tests, self.reloads = fail, 0, 0

    def test_nginx(self):
        self.tests += 1
        if self.fail:
            raise RuntimeError("nginx: [emerg] test failed")

    def reload_nginx(self):
        self.reloads += 1


def test_sync_writes_tests_and_reloads_once(monkeypatch):
    rm = _Rm()
    monkeypatch.setattr(ml_gate, "_rule_manager", rm)
    monkeypatch.setattr(ml_gate, "enforcing_policies", lambda: {"o1": "enforce:88:95"})
    db = _Db([("shop.example.com", "o1"), ("other.example.com", "o2")])
    assert ml_gate.sync(db) is True
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {"shop.example.com": "enforce:88:95"}
    assert (rm.tests, rm.reloads) == (1, 1)
    assert ml_gate.sync(db) is False and rm.reloads == 1  # nothing changed: no reload


def test_a_host_claimed_by_two_origins_stays_in_log_mode(monkeypatch):
    monkeypatch.setattr(ml_gate, "_rule_manager", _Rm())
    monkeypatch.setattr(ml_gate, "enforcing_policies", lambda: {"o1": "enforce:88:95"})
    ml_gate.sync(_Db([("shared.example.com", "o1"), ("shared.example.com", "o2")]))
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {}


def test_a_map_nginx_refuses_is_put_back(monkeypatch):
    monkeypatch.setattr(ml_gate, "_rule_manager", _Rm())
    monkeypatch.setattr(ml_gate, "enforcing_policies", lambda: {"o1": "enforce:88:95"})
    ml_gate.sync(_Db([("shop.example.com", "o1")]))
    before = ml_gate.read_map()
    monkeypatch.setattr(ml_gate, "_rule_manager", _Rm(fail=True))
    monkeypatch.setattr(ml_gate, "enforcing_policies", lambda: {"o1": "enforce:50:60"})
    with pytest.raises(RuntimeError):
        ml_gate.sync(_Db([("shop.example.com", "o1")]))
    assert ml_gate.read_map() == before
    assert "test failed" in ml_gate.status()["last_error"]


def test_a_first_map_nginx_refuses_leaves_no_file(monkeypatch):
    monkeypatch.setattr(ml_gate, "_rule_manager", _Rm(fail=True))
    monkeypatch.setattr(ml_gate, "enforcing_policies", lambda: {})
    ml_gate.sync_quietly(_Db([]))
    assert ml_gate.read_map() is None


# ---- settings API ---------------------------------------------------------------

@pytest.fixture()
def team(client, register_user, auth_header):
    client.app.include_router(ml_protection.router)
    support = register_user(email="mlp-support@example.com", username="mlp_support")  # first account = operator
    owner = register_user(email="mlp-owner@example.com", username="mlp_owner")
    editor = register_user(email="mlp-editor@example.com", username="mlp_editor")
    viewer = register_user(email="mlp-viewer@example.com", username="mlp_viewer")
    stranger = register_user(email="mlp-stranger@example.com", username="mlp_stranger")
    h = {k: auth_header(u["access_token"]) for k, u in
         (("support", support), ("owner", owner), ("editor", editor), ("viewer", viewer), ("stranger", stranger))}
    oid = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.71", "port": 80},
                      headers=h["owner"]).json()["id"]
    for u, role in ((editor, "editor"), (viewer, "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)",
                   (oid, u["user"]["user_id"], role))
    seed_domain(tenant_service.db, {"origin_id": oid, "domain_name": "mlp-shop.example.com", "dns_verified": True})
    tenant_service._TENANT_CACHE.clear()
    return oid, h


ENFORCE = {"mode": "enforce", "challenge_score": 88, "block_score": 95}


def test_log_is_the_default_and_nothing_is_in_the_map(client, team):
    oid, h = team
    r = client.get(f"/api/origins/{oid}/ml-protection", headers=h["viewer"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["mode"], body["challenge_score"], body["block_score"]) == ("log", 88, 95)
    assert body["hosts"] == ["mlp-shop.example.com"] and body["applied"] is True


def test_owner_turns_on_enforce_and_the_map_carries_the_bands(client, team):
    oid, h = team
    r = client.put(f"/api/origins/{oid}/ml-protection", json=ENFORCE, headers=h["owner"])
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "enforce" and r.json()["applied"] is True
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {"mlp-shop.example.com": "enforce:88:95"}

    back = client.put(f"/api/origins/{oid}/ml-protection", json={**ENFORCE, "mode": "log"}, headers=h["editor"])
    assert back.status_code == 200 and back.json()["applied"] is True
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {}


def test_every_change_is_audited_with_before_and_after(client, team):
    oid, h = team
    client.put(f"/api/origins/{oid}/ml-protection", json=ENFORCE, headers=h["editor"])
    events = [e for e in audit_log.get_audit_log(oid, db=audit_log.db) if e["action"] == "ml_protection.update"]
    assert len(events) == 1
    assert events[0]["actor_username"] == "mlp_editor"
    assert events[0]["details"]["before"]["mode"] == "log" and events[0]["details"]["after"]["mode"] == "enforce"


def test_viewers_read_only_and_strangers_see_nothing(client, team):
    oid, h = team
    assert client.put(f"/api/origins/{oid}/ml-protection", json=ENFORCE, headers=h["viewer"]).status_code == 403
    assert client.put(f"/api/origins/{oid}/ml-protection", json=ENFORCE, headers=h["stranger"]).status_code in (403, 404)
    assert client.get(f"/api/origins/{oid}/ml-protection", headers=h["stranger"]).status_code in (403, 404)
    assert client.get(f"/api/origins/{oid}/ml-protection/preview", params={"block_score": 95},
                      headers=h["stranger"]).status_code in (403, 404)
    assert ml_gate.get_settings(oid)["mode"] == "log"


@pytest.mark.parametrize("body", [
    {"mode": "enforce", "challenge_score": 95, "block_score": 95},
    {"mode": "enforce", "challenge_score": 96, "block_score": 95},
    {"mode": "enforce", "challenge_score": 40, "block_score": 95},
    {"mode": "enforce", "challenge_score": 88, "block_score": 101},
    {"mode": "block-everything", "challenge_score": 88, "block_score": 95},
])
def test_bad_bands_are_refused_and_nothing_changes(client, team, body):
    oid, h = team
    assert client.put(f"/api/origins/{oid}/ml-protection", json=body, headers=h["owner"]).status_code == 422
    assert ml_gate.get_settings(oid)["mode"] == "log"


def test_no_challenge_band_is_allowed(client, team):
    oid, h = team
    r = client.put(f"/api/origins/{oid}/ml-protection",
                   json={"mode": "enforce", "challenge_score": None, "block_score": 97}, headers=h["owner"])
    assert r.status_code == 200, r.text
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {"mlp-shop.example.com": "enforce:0:97"}


def test_an_archived_origin_leaves_the_map(client, team):
    oid, h = team
    client.put(f"/api/origins/{oid}/ml-protection", json=ENFORCE, headers=h["owner"])
    pool.exec_("UPDATE origins SET status = 'archived' WHERE id = %s", (oid,))
    ml_gate.sync(ml_protection.db)
    assert ml_gate.hosts_in_map(ml_gate.read_map()) == {}


def test_preview_reads_only_this_origins_hosts(client, team, monkeypatch):
    oid, h = team
    monkeypatch.setattr(ml_protection.ch, "connected", True)
    seen = {}

    def fake_preview(ch, scope, challenge, block, hours):
        seen.update(scope=scope, challenge=challenge, block=block, hours=hours)
        return {"hours": hours, "total": 10, "would_block": 1, "would_challenge": 2, "since": 1, "examples": []}

    monkeypatch.setattr(ml_protection.ml_gate, "preview", fake_preview)
    r = client.get(f"/api/origins/{oid}/ml-protection/preview",
                   params={"block_score": 95, "challenge_score": 88}, headers=h["viewer"])
    assert r.status_code == 200, r.text
    assert seen == {"scope": "((host = 'mlp-shop.example.com'))", "challenge": 88, "block": 95, "hours": 168}
    bad = client.get(f"/api/origins/{oid}/ml-protection/preview",
                     params={"block_score": 90, "challenge_score": 90}, headers=h["viewer"])
    assert bad.status_code == 422


def test_preview_query_counts_each_band_once():
    calls = []

    class _CH:
        def query(self, sql, parameters=None):
            calls.append((sql, parameters))
            if "count()" in sql:
                return types.SimpleNamespace(result_rows=[(100, 3, 7, 1790000000)])
            return types.SimpleNamespace(result_rows=[(1790000001, "a.example.com", "POST", "/x", 0.97)])

    out = ml_gate.preview(types.SimpleNamespace(client=_CH()), "(host = 'a.example.com')", 88, 95, 168)
    assert out == {"hours": 168, "total": 100, "would_block": 3, "would_challenge": 7, "since": 1790000000,
                   "examples": [{"timestamp": 1790000001, "host": "a.example.com", "method": "POST", "path": "/x",
                                 "score": 0.97}]}
    sql, params = calls[0]
    assert "(host = 'a.example.com')" in sql and params == {"hours": 168, "block": 95.0, "challenge": 88.0}
    # no challenge band: nothing is counted as challenged
    assert ml_gate.preview(types.SimpleNamespace(client=_CH()), "1=1", None, 95)["would_challenge"] == 0


# ---- the relay nginx's gate calls ------------------------------------------------

class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    answer: ClassVar[object] = None
    seen: ClassVar[list] = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **k):
        _Client.seen.append((url, k))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


VERDICT = {"request_id": "rid-9", "host": "shop.example.com", "method": "POST", "path": "/api/login", "query": "",
           "score": 0.97, "threshold": 0.8749, "is_attack": True, "detectors": [], "body_length": 40,
           "feature_set": "gen3-F"}


@pytest.fixture()
def relay(monkeypatch):
    ml_verdicts._buffer.clear()
    monkeypatch.setattr(ml_verdicts, "ENABLED", True)
    _Client.seen = []
    monkeypatch.setattr(ml_module, "httpx", types.SimpleNamespace(
        AsyncClient=_Client, RequestError=httpx.RequestError, HTTPStatusError=httpx.HTTPStatusError))
    monkeypatch.setattr(ml_module, "_is_internal_relay_request", lambda request: True)
    monkeypatch.setattr(ml_module, "ML_CAPTURE_URL", "http://127.0.0.1:5000")
    app = FastAPI()
    app.include_router(ml_module.router)
    yield TestClient(app)
    ml_verdicts._buffer.clear()


def _gate(client, policy="enforce:88:95", body=b'{"q":"x"}'):
    return client.post("/api/ml/gate", content=body,
                       headers={"X-ML-Gate": policy, "X-Original-URI": "/api/login", "X-Original-Host": "shop.example.com",
                                "X-Original-Method": "POST", "Content-Type": "application/json"})


@pytest.mark.parametrize("score, action", [(0.97, "block"), (0.9, "challenge"), (0.2, "pass")])
def test_relay_answers_the_band_and_records_it(relay, score, action):
    _Client.answer = _Resp(200, {**VERDICT, "score": score})
    r = _gate(relay)
    assert r.status_code == 204
    assert r.headers["X-WAF-ML-Action"] == action and r.headers["X-WAF-ML-Score"] == f"{score:.4f}"
    row = dict(zip(ml_verdicts.COLUMNS, ml_verdicts._buffer[-1]))
    assert row["action"] == action and row["request_id"] == "rid-9"
    url, kwargs = _Client.seen[-1]
    assert url.endswith("/capture") and kwargs["content"] == b'{"q":"x"}'  # scored with the body


def test_relay_without_a_policy_passes_without_calling_ml(relay):
    for policy in ("", "log", "enforce:99:10"):
        r = _gate(relay, policy=policy)
        assert r.headers["X-WAF-ML-Action"] == "pass"
    assert _Client.seen == [] and len(ml_verdicts._buffer) == 0


@pytest.mark.parametrize("answer", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), _Resp(503),
                                    _Resp(200, {"score": "high"}), _Resp(200, ["not", "a", "verdict"])])
def test_relay_fails_open(relay, answer):
    _Client.answer = answer
    r = _gate(relay)
    assert r.status_code == 204 and r.headers["X-WAF-ML-Action"] == "pass" and r.headers["X-WAF-ML-Error"]


def test_relay_refuses_callers_without_the_secret(monkeypatch):
    monkeypatch.setattr(ml_module, "INTERNAL_RELAY_SECRET", "s3cret")
    app = FastAPI()
    app.include_router(ml_module.router)
    assert _gate(TestClient(app)).status_code == 404


def test_a_mirrored_verdict_has_no_action_and_an_unknown_one_is_dropped():
    ml_verdicts._buffer.clear()
    ml_verdicts.enqueue(VERDICT)
    ml_verdicts.enqueue({**VERDICT, "action": "nuke"})
    assert [dict(zip(ml_verdicts.COLUMNS, r))["action"] for r in ml_verdicts._buffer] == ["", ""]
    ml_verdicts._buffer.clear()


# ---- direct-mode site files carry the gate ------------------------------------

def test_site_file_sends_location_slash_through_the_gate():
    from services import nginx_site_service as nss
    text = nss.generate_site_nginx_config("shop.example.com", {"ip": "203.0.113.10", "port": 8080})
    slash = text[text.index("    location / {"):text.index("    location @waf_origin {")]
    assert "js_content mlgate.gate;" in slash and "proxy_pass" not in slash
    assert "auth_request /internal-shield-check;" in slash and "mirror /internal-ml-capture;" in slash
    origin = text[text.index("    location @waf_origin {"):]
    assert "proxy_pass http://203.0.113.10:8080;" in origin
    assert 'more_set_headers "Cache-Control: $waf_cache_control";' in origin
