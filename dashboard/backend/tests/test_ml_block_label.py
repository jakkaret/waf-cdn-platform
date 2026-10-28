"""An ML gate block reads as an ML block in the logs, not as ModSecurity's.

Found live 2026-10-28 on demo-final.originweb.site (enforce:0:60): the gate
returned 403 for a GraphQL introspection POST (ml_verdicts action=block, 0.926),
and its access_logs row -- written from the edge's log, not Main's -- said
attack_type "WAF Security Block", rule_id "WAF-CRS", like any CRS block. The
edge and Main also gave the request different ids, so nothing could join them.

What must hold: nginx sends the edge's request id to the ML relays; the relay
remembers a block/challenge under it; the edge's row for that id is labelled
ML-GEN3 at ingest; every other row is unchanged; a label is forgotten after
its TTL; the explanation of an ML row does not blame a WAF rule."""
from pathlib import Path

import pytest

import api.cdn as cdn_module
from services import ml_gate
from services.explainability_service import ML_CATEGORY, explainability_service
from services.log_normalize import ML_RULE_ID, label_ml_action, normalize_cdn_access
from tests.test_ml_gate import VERDICT, _Client, _Resp, relay  # noqa: F401  (relay is a fixture)

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def no_actions():
    ml_gate._actions.clear()
    yield
    ml_gate._actions.clear()


# ---- nginx: the ML relays carry the edge's id --------------------------------

def test_ml_relays_send_the_edge_request_id():
    default = (REPO / "nginx/templates/conf.d/default.conf.template").read_text(encoding="utf-8")
    assert 'map $http_x_request_id $waf_request_id {' in default
    assert '"~^[0-9a-f]{32}$" $http_x_request_id;' in default
    assert "default           $request_id;" in default
    captcha = (REPO / "nginx/templates/includes/captcha_server.conf.template").read_text(encoding="utf-8")
    for location in ("location = /internal-ml-capture {", "location = /internal-ml-gate {"):
        block = captcha[captcha.index(location):]
        block = block[:block.index("\n}\n")]
        assert "proxy_set_header X-Original-Request-ID $waf_request_id;" in block, location


# ---- the remembered action ---------------------------------------------------

def test_block_and_challenge_are_remembered_pass_is_not():
    ml_gate.remember_action("a" * 32, "block", now=100.0)
    ml_gate.remember_action("b" * 32, "challenge", now=100.0)
    ml_gate.remember_action("c" * 32, "pass", now=100.0)
    ml_gate.remember_action("", "block", now=100.0)
    assert ml_gate.recalled_action("a" * 32, now=101.0) == "block"
    assert ml_gate.recalled_action("b" * 32, now=101.0) == "challenge"
    assert ml_gate.recalled_action("c" * 32, now=101.0) is None
    assert ml_gate.recalled_action("", now=101.0) is None
    assert ml_gate.recalled_action(None, now=101.0) is None


def test_an_action_is_forgotten_after_its_ttl():
    ml_gate.remember_action("a" * 32, "block", now=0.0)
    assert ml_gate.recalled_action("a" * 32, now=ml_gate.ACTION_TTL_SECONDS - 1) == "block"
    assert ml_gate.recalled_action("a" * 32, now=ml_gate.ACTION_TTL_SECONDS + 1) is None
    ml_gate.remember_action("b" * 32, "block", now=ml_gate.ACTION_TTL_SECONDS + 2)
    assert "a" * 32 not in ml_gate._actions  # expired entries are dropped, not kept forever


def test_memory_is_capped(monkeypatch):
    monkeypatch.setattr(ml_gate, "ACTIONS_MAX", 3)
    for i in range(5):
        ml_gate.remember_action(f"rid-{i}", "block", now=10.0)
    assert list(ml_gate._actions) == ["rid-2", "rid-3", "rid-4"]


@pytest.mark.parametrize("score, action", [(0.97, "block"), (0.9, "challenge"), (0.2, "pass")])
def test_relay_remembers_its_answer_under_the_edge_id(relay, score, action):  # noqa: F811
    _Client.answer = _Resp(200, {**VERDICT, "score": score})
    edge_rid = "d8da510bc60e7b47e4287e094e929154"
    r = relay.post("/api/ml/gate", content=b'{"q":"x"}',
                   headers={"X-ML-Gate": "enforce:88:95", "X-Original-Request-ID": edge_rid,
                            "X-Original-Host": "shop.example.com", "X-Original-URI": "/api/login",
                            "X-Original-Method": "POST", "Content-Type": "application/json"})
    assert r.headers["X-WAF-ML-Action"] == action
    assert ml_gate.recalled_action(edge_rid) == (None if action == "pass" else action)


# ---- the edge's row at ingest --------------------------------------------------

class _CapturingClickHouse:
    connected = True

    def __init__(self):
        self.rows = []

    def save_logs_bulk(self, table_name, entries):
        self.rows = entries
        return len(entries)


def _edge_entry(rid, status):
    return {"request_id": rid, "remote_addr": "203.0.113.5", "method": "POST", "request_uri": "/api/gql",
            "status": status, "host": "demo-final.originweb.site"}


def test_ingest_labels_only_the_rows_the_gate_answered(monkeypatch):
    ch = _CapturingClickHouse()
    monkeypatch.setattr(cdn_module, "ch", ch)
    ml_gate.remember_action("rid-ml-block", "block")
    ml_gate.remember_action("rid-ml-challenge", "challenge")

    _stored, flagged = cdn_module._store_cdn_log_batch([
        _edge_entry("rid-ml-block", "403"),
        _edge_entry("rid-crs-block", "403"),
        _edge_entry("rid-ml-challenge", "401"),
        _edge_entry("rid-ok", "200"),
    ], "th")

    by_rid = {r["request_id"]: r for r in ch.rows}
    assert (by_rid["rid-ml-block"]["attack_type"], by_rid["rid-ml-block"]["rule_id"]) == ("ML Block", ML_RULE_ID)
    assert (by_rid["rid-ml-challenge"]["attack_type"], by_rid["rid-ml-challenge"]["rule_id"]) == ("ML Challenge", ML_RULE_ID)
    # Untouched: a ModSecurity block keeps its placeholder, a pass stays empty.
    assert (by_rid["rid-crs-block"]["attack_type"], by_rid["rid-crs-block"]["rule_id"]) == ("WAF Security Block", "WAF-CRS")
    assert (by_rid["rid-ok"]["attack_type"], by_rid["rid-ok"]["rule_id"]) == (None, None)
    # Alerts still fire for the ML block, with its own label.
    assert {f["request_id"]: f["attack_type"] for f in flagged} == {"rid-ml-block": "ML Block",
                                                                    "rid-crs-block": "WAF Security Block"}


def test_label_without_an_action_changes_nothing():
    row = normalize_cdn_access(_edge_entry("rid-x", "403"), "th")
    before = dict(row)
    assert label_ml_action(row, None) == before
    assert label_ml_action(row, "pass") == before


# ---- the explanation ---------------------------------------------------------

def test_an_ml_row_is_not_explained_as_a_waf_rule():
    exp = explainability_service.explain_event({"url": "/api/gql", "method": "POST", "status": 403,
                                                "rule_id": ML_RULE_ID, "attack_type": "ML Block"})
    assert exp["category"] == ML_CATEGORY
    assert "ML" in exp["root_cause_explanation"] and "ML insights" in exp["remediation_hint"]
