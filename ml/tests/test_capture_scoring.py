"""/capture scores every mirrored request with Gen 3 (ML Insights).

nginx mirrors each request (body included) to /capture. The lab telemetry
(capture_request) must keep working exactly as before; on top of it the
endpoint answers the Gen 3 verdict for any host. The verdict is what the
dashboard stores and shows tenants, so it must never carry the body, must
redact sensitive query values, and the endpoint must fail open (204) whenever
there is no verdict to give.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("onnxruntime", reason="onnxruntime not installed")
pytest.importorskip("libinjection", reason="libinjection-python not installed")

from ml import ml_api  # noqa: E402

SQLI_BODY = b'{"username": "admin\' UNION SELECT username,password FROM users--", "remember": true}'


@pytest.fixture(scope="module")
def gen3():
    if not os.path.exists(ml_api.GEN3_ONNX_PATH):
        pytest.skip(f"Gen 3 model not found: {ml_api.GEN3_ONNX_PATH}")
    model, error = ml_api.load_gen3_model()
    if model is None:
        pytest.skip(f"Gen 3 model not loadable: {error}")
    return model


@pytest.fixture
def client(monkeypatch, gen3):
    calls = []
    monkeypatch.setattr(ml_api, "gen3_model", gen3)
    monkeypatch.setattr(ml_api, "CAPTURE_SCORING", True)
    monkeypatch.setattr(ml_api, "capture_request", lambda **kw: calls.append(kw))
    # No context manager: the startup event (all models, bind check) is not needed here.
    return TestClient(ml_api.app), calls


def _capture(client, body=b"", uri="/", method="GET", host="shop.example.com", content_type=""):
    return client.post("/capture", content=body, headers={
        "X-Original-Host": host, "X-Original-URI": uri, "X-Original-Method": method,
        "X-Original-Request-ID": "rid-1", "Content-Type": content_type,
    })


def test_attack_in_json_body_is_scored_and_named(client):
    c, _ = client
    resp = _capture(c, SQLI_BODY, uri="/api/login", method="POST", content_type="application/json")
    assert resp.status_code == 200
    v = resp.json()
    assert v["is_attack"] is True
    assert v["score"] >= v["threshold"]
    assert "v_sqli_libinjection" in v["detectors"]
    assert (v["request_id"], v["host"], v["method"], v["path"]) == ("rid-1", "shop.example.com", "POST", "/api/login")
    assert v["body_length"] == len(SQLI_BODY)


def test_verdict_never_carries_the_body(client):
    c, _ = client
    v = _capture(c, SQLI_BODY, uri="/api/login", method="POST", content_type="application/json").json()
    dumped = json.dumps(v)
    assert "UNION" not in dumped and "password" not in dumped and "body" not in v


def test_sensitive_query_values_are_redacted(client):
    c, _ = client
    v = _capture(c, uri="/cb?token=s3cr3t-value&page=2").json()
    assert "s3cr3t-value" not in json.dumps(v)
    assert "token=%3CREDACTED%3E" in v["query"] and "page=2" in v["query"]


def test_benign_request_is_scored_low_without_detectors(client):
    c, _ = client
    v = _capture(c, uri="/products?page=2&sort=price").json()
    assert v["is_attack"] is False and v["score"] < ml_api.CAPTURE_DETECTOR_FLOOR
    assert v["detectors"] == []


def test_any_host_is_scored_not_only_the_lab_allowlist(client):
    c, _ = client
    assert _capture(c, uri="/?id=1%27%20OR%201=1--", host="t-abc.tunnel.originweb.site").status_code == 200


def test_lab_telemetry_still_receives_the_same_arguments(client):
    c, calls = client
    _capture(c, b"a=1", uri="/x?y=1", method="POST", host="dvwa.waf-it-kku.online",
             content_type="application/x-www-form-urlencoded")
    assert calls == [{"host": "dvwa.waf-it-kku.online", "method": "POST", "uri": "/x?y=1", "request_id": "rid-1",
                      "content_type": "application/x-www-form-urlencoded", "body": b"a=1"}]


def test_no_model_answers_204_and_telemetry_still_runs(client, monkeypatch):
    c, calls = client
    monkeypatch.setattr(ml_api, "gen3_model", None)
    assert _capture(c, uri="/").status_code == 204
    assert len(calls) == 1


def test_scoring_switched_off_answers_204(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(ml_api, "CAPTURE_SCORING", False)
    assert _capture(c, uri="/?id=1%27%20OR%201=1--").status_code == 204


def test_scoring_failure_fails_open(client, monkeypatch):
    c, _ = client

    def boom(**_kw):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(ml_api, "score_captured", boom)
    assert _capture(c, uri="/").status_code == 204


def test_telemetry_failure_does_not_stop_scoring(client, monkeypatch):
    c, _ = client

    def broken(**_kw):
        raise OSError("disk full")

    monkeypatch.setattr(ml_api, "capture_request", broken)
    assert _capture(c, uri="/").status_code == 200
