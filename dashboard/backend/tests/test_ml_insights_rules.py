"""ML Insights -> rule (2026-10-27): the masked body kept with a flagged verdict,
who may read it, and proposing a rule from one scored request.

What must hold: a body is kept only from score 50 up and never with a
password, token, card number, e-mail or phone number in it; insights lists
never carry the body; only the origin's Owner/Editors read it or propose a
rule, and only for their own origin's requests; a request ML already blocks,
or one below the model threshold, gets no proposal; a proposal lands in the
origin's pending queue and is never approved here."""
import types
from unittest.mock import MagicMock

import pytest

import services.ml_rule_service as ml_rule_service_module
from api import ml as ml_module
from api import ml_protection
from db import pool
from services import ml_verdicts as mv
from services import tenant_service
from tests.helpers.seed import seed_domain


# ---- masking -------------------------------------------------------------------

@pytest.mark.parametrize("body, gone, kept", [
    ('{"user":"alice","password":"hunter2"}', "hunter2", "alice"),
    ("user=alice&password=hunter2&next=/", "hunter2", "next=/"),
    ("password=hunter2&user=alice", "hunter2", "user=alice"),
    ('{"note":"call me 0812345678"}', "0812345678", "call me"),
    ('{"email":"alice@example.com"}', "alice@example.com", "email"),
    ('{"card":"4111 1111 1111 1111"}', "4111 1111 1111 1111", "card"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz", "Bearer"),
    ('------b\r\nContent-Disposition: form-data; name="password"\r\n\r\nhunter2\r\n------b--', "hunter2", 'name="password"'),
    ('------b\r\nContent-Disposition: form-data; name="otp"\r\nContent-Type: text/plain\r\n\r\n123456\r\n------b--', "123456", 'name="otp"'),
])
def test_secrets_and_pii_are_masked(body, gone, kept):
    out = mv.mask_body(body)
    assert gone not in out and kept in out


def test_the_attack_itself_survives_masking():
    payload = "{\"q\":\"1' UNION SELECT username,password FROM users--\"}"
    assert "UNION SELECT username,password FROM users" in mv.mask_body(payload)


def test_a_body_is_kept_only_from_the_watch_floor_up():
    assert mv.body_sample(b'{"a":"b"}', 0.49) == ""
    assert mv.body_sample(b'{"a":"b"}', 0.5) == '{"a":"b"}'
    assert mv.body_sample(b"", 0.99) == "" and mv.body_sample(None, 0.99) == ""
    assert mv.body_sample(b"x" * 10000, 0.9) == "x" * mv.BODY_SAMPLE_MAX
    assert mv.body_sample(b"\xff\xfeok", 0.9).endswith("ok")  # bad UTF-8 does not drop the sample


VERDICT = {"request_id": "rid-7", "host": "mlr-shop.example.com", "method": "POST", "path": "/api/search", "query": "",
           "score": 0.93, "threshold": 0.8749, "is_attack": True, "detectors": ["v_sqli_libinjection"],
           "body_length": 40, "feature_set": "gen3-F"}


def test_the_buffered_row_holds_the_masked_sample_only(monkeypatch):
    mv._buffer.clear()
    monkeypatch.setattr(mv, "ENABLED", True)
    mv.enqueue(VERDICT, body=b'{"q":"1 OR 1=1","password":"hunter2"}')
    mv.enqueue({**VERDICT, "score": 0.2, "is_attack": False}, body=b'{"q":"hello"}')
    rows = [dict(zip(mv.COLUMNS, r)) for r in mv._buffer]
    assert "hunter2" not in rows[0]["body_sample"] and "1 OR 1=1" in rows[0]["body_sample"]
    assert rows[1]["body_sample"] == ""
    mv._buffer.clear()


def test_insights_lists_carry_a_flag_not_the_body():
    calls = []

    class _CH:
        def query(self, sql, parameters=None):
            calls.append(sql)
            if "uniqExact(host)" in sql:
                return types.SimpleNamespace(result_rows=[(1, 1, 0, 1, 1790000000, 0.8749, "gen3-F", 0, 0)])
            if "FROM ml_verdicts" in sql and "ORDER BY timestamp DESC, score DESC" in sql:
                return types.SimpleNamespace(result_rows=[(1790000000, "rid-7", "h", "POST", "/", "", 0.93, 0.87, 1, [], 40, "", 1)])
            return types.SimpleNamespace(result_rows=[])

    out = mv.insights(types.SimpleNamespace(client=_CH()), "1=1")
    listing = next(s for s in calls if "ORDER BY timestamp DESC, score DESC" in s)
    assert "body_sample != ''" in listing and "body_sample," not in listing
    assert out["requests"][0]["has_body"] is True and "body_sample" not in out["requests"][0]


# ---- who may propose -------------------------------------------------------------

def test_can_propose_follows_role_score_and_what_the_gate_did(monkeypatch):
    import api.ml_rules as ml_rules_module
    import services.shield_sync as shield_sync
    monkeypatch.setattr(shield_sync, "desired_hostmap", lambda db: {"a.example.com": "o1", "b.example.com": "o2"})
    monkeypatch.setattr(ml_rules_module, "_member_roles", lambda uid: {"o1": "editor", "o2": "viewer"})
    reqs = [
        {"host": "a.example.com", "is_attack": True, "action": None},          # log mode, flagged
        {"host": "a.example.com", "is_attack": True, "action": "challenge"},   # enforce, challenge band
        {"host": "a.example.com", "is_attack": True, "action": "block"},       # ML blocked it already
        {"host": "a.example.com", "is_attack": False, "action": None},         # below the model threshold
        {"host": "b.example.com", "is_attack": True, "action": None},          # a viewer there
        {"host": "c.example.com", "is_attack": True, "action": None},          # not in the host map
    ]
    ml_module._mark_proposable(reqs, {"user_id": "u1"})
    assert [r["can_propose"] for r in reqs] == [True, True, False, False, False, False]
    assert [r["can_edit"] for r in reqs] == [True, True, True, True, False, False]
    assert reqs[0]["origin_id"] == "o1" and reqs[5]["origin_id"] is None


# ---- the endpoints -------------------------------------------------------------------

class _VerdictCH:
    """ClickHouse stand-in for get_verdict: answers a row only when the
    query's scope names the stored row's host."""
    connected = True

    def __init__(self, rows):
        self.rows = rows
        self.client = self

    def query(self, sql, parameters=None):
        for r in self.rows:
            if f"host = '{r['host']}'" in sql and parameters.get("rid") == r["request_id"]:
                return types.SimpleNamespace(result_rows=[(
                    1790000000, r["request_id"], r["host"], r["method"], r["path"], r["query"], r["score"],
                    r["threshold"], 1 if r["is_attack"] else 0, r["detectors"], r["body_length"], r.get("action", ""),
                    r.get("body_sample", ""))])
        return types.SimpleNamespace(result_rows=[])


@pytest.fixture()
def team(client, register_user, auth_header, monkeypatch):
    client.app.include_router(ml_protection.router)
    register_user(email="mlr-support@example.com", username="mlr_support")  # first account = operator
    owner = register_user(email="mlr-owner@example.com", username="mlr_owner")
    editor = register_user(email="mlr-editor@example.com", username="mlr_editor")
    viewer = register_user(email="mlr-viewer@example.com", username="mlr_viewer")
    stranger = register_user(email="mlr-stranger@example.com", username="mlr_stranger")
    h = {k: auth_header(u["access_token"]) for k, u in
         (("owner", owner), ("editor", editor), ("viewer", viewer), ("stranger", stranger))}
    oid = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.72", "port": 80}, headers=h["owner"]).json()["id"]
    other = client.post("/api/origins", json={"label": "other", "ip": "203.0.113.73", "port": 80},
                        headers=h["stranger"]).json()["id"]
    for u, role in ((editor, "editor"), (viewer, "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)", (oid, u["user"]["user_id"], role))
    seed_domain(tenant_service.db, {"origin_id": oid, "domain_name": "mlr-shop.example.com", "dns_verified": True})
    seed_domain(tenant_service.db, {"origin_id": other, "domain_name": "mlr-other.example.com", "dns_verified": True})
    tenant_service._TENANT_CACHE.clear()
    rows = [
        {**VERDICT, "body_sample": '{"q":"1 OR 1=1","password":"[MASKED_PASSWORD]"}'},
        {**VERDICT, "request_id": "rid-blocked", "action": "block"},
        {**VERDICT, "request_id": "rid-low", "score": 0.6, "is_attack": False},
        {**VERDICT, "request_id": "rid-other", "host": "mlr-other.example.com"},
    ]
    monkeypatch.setattr(ml_protection, "ch", _VerdictCH(rows))
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())

    class _AllowAll:
        def is_allowed(self, *a, **k):
            return True, 1, 0

    monkeypatch.setattr(ml_module, "_suggest_limiter", _AllowAll())
    return oid, other, h


def test_owner_and_editor_read_the_masked_body_viewers_do_not(client, team):
    oid, _other, h = team
    r = client.get(f"/api/origins/{oid}/ml-verdicts/rid-7", headers=h["editor"])
    assert r.status_code == 200, r.text
    assert r.json()["body_sample"].endswith('"[MASKED_PASSWORD]"}')
    assert client.get(f"/api/origins/{oid}/ml-verdicts/rid-7", headers=h["viewer"]).status_code == 403
    assert client.get(f"/api/origins/{oid}/ml-verdicts/rid-7", headers=h["stranger"]).status_code in (403, 404)


def test_another_origins_request_is_not_found_through_your_origin(client, team):
    oid, _other, h = team
    assert client.get(f"/api/origins/{oid}/ml-verdicts/rid-other", headers=h["owner"]).status_code == 404
    assert client.post(f"/api/origins/{oid}/ml-verdicts/rid-other/suggest-rule", headers=h["owner"]).status_code == 404


class _Resp:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
        self.text = str(data)

    def json(self):
        return self._data


class _FakeML:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, *_a, **_k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def post(self, url, json=None, **_kwargs):
        path = "/" + url.rsplit("/", 1)[-1]
        self.calls.append((path, json))
        return self.routes[path]


RULE = {"pattern": "@detectSQLi", "variable": "ARGS|REQUEST_BODY", "attack_type": "SQL Injection", "severity": "CRITICAL",
        "secrule_template": 'SecRule ARGS "@detectSQLi" "id:{RULE_ID},deny"', "source_url": "/api/search",
        "source_method": "POST", "generator": "gen3-detector", "detector": "v_sqli_libinjection",
        "dedup_key": "gen3-detector:v_sqli_libinjection"}


def test_a_flagged_request_becomes_a_pending_rule_of_that_origin(client, team, monkeypatch):
    oid, _other, h = team
    fake = _FakeML({"/predict-gen3": _Resp(200, {"is_attack": True, "attack_probability": 0.95, "threshold": 0.8749}),
                    "/generate-rule-gen3": _Resp(200, {"rules": [RULE]})})
    monkeypatch.setattr(ml_module.httpx, "AsyncClient", fake)
    r = client.post(f"/api/origins/{oid}/ml-verdicts/rid-7/suggest-rule", headers=h["editor"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["suggestion"]["created"] == 1 and body["suggestion"]["origin_id"] == oid
    rule = body["suggested_rules"][0]
    assert rule["status"] == "pending" and rule["origin_id"] == oid and rule["can_review"] is True
    # rescored from what was stored: the masked body, never the original secret
    sent = fake.calls[0][1]
    assert sent["url"] == "/api/search" and sent["method"] == "POST" and "[MASKED_PASSWORD]" in sent["body"]
    again = client.post(f"/api/origins/{oid}/ml-verdicts/rid-7/suggest-rule", headers=h["owner"]).json()
    assert again["suggestion"]["merged"] == 1  # the same detector joins the same pending rule


def test_no_proposal_for_a_blocked_or_low_request_or_from_a_viewer(client, team):
    oid, _other, h = team
    assert client.post(f"/api/origins/{oid}/ml-verdicts/rid-blocked/suggest-rule", headers=h["owner"]).status_code == 409
    assert client.post(f"/api/origins/{oid}/ml-verdicts/rid-low/suggest-rule", headers=h["owner"]).status_code == 422
    assert client.post(f"/api/origins/{oid}/ml-verdicts/rid-7/suggest-rule", headers=h["viewer"]).status_code == 403
    assert client.post(f"/api/origins/{oid}/ml-verdicts/missing/suggest-rule", headers=h["owner"]).status_code == 404


def test_the_relays_pass_the_body_on_with_the_verdict(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *a, **k):
            return _Resp(200, VERDICT)

    mv._buffer.clear()
    monkeypatch.setattr(mv, "ENABLED", True)
    monkeypatch.setattr(ml_module, "httpx", types.SimpleNamespace(AsyncClient=_Client, RequestError=Exception,
                                                                  HTTPStatusError=Exception))
    monkeypatch.setattr(ml_module, "_is_internal_relay_request", lambda request: True)
    monkeypatch.setattr(ml_module, "ML_CAPTURE_URL", "http://127.0.0.1:5000")
    app = FastAPI()
    app.include_router(ml_module.router)
    c = TestClient(app)
    c.post("/api/ml/capture", content=b'{"q":"x","token":"abc123secret"}', headers={"X-Original-Host": "h"})
    c.post("/api/ml/gate", content=b'{"q":"y"}', headers={"X-ML-Gate": "enforce:88:95"})
    samples = [dict(zip(mv.COLUMNS, r))["body_sample"] for r in mv._buffer]
    assert len(samples) == 2 and "abc123secret" not in samples[0] and '"q":"x"' in samples[0] and samples[1] == '{"q":"y"}'
    mv._buffer.clear()
