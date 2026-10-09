#!/usr/bin/env python3
"""
WAF decision endpoint for measuring the Gen 3 model's detection on a LOCAL test host.

This is a DEFENSIVE test rig: it fronts a fake origin, scores every incoming
request with the Gen 3 model exactly as ml_api would, and answers 403 when the
model flags an attack and 200 otherwise. Point a WAF-efficacy tool (GoTestWAF,
Nuclei, sqlmap) at it and its "blocked" count becomes the model's detection rate,
its benign requests becoming the false-positive rate. Nothing here attacks anything.

Run against localhost only, on your own machine, never the production VPS.

    WAF_GEN3_ONNX_PATH=ml/models/gen3/gen3_f_noopenappsec.onnx \
      PYTHONPATH=. uvicorn ml.security_test.waf_test_harness:app --host 127.0.0.1 --port 8088

Every decision is appended as JSON to $WAF_TEST_LOG (default security_test/decisions.jsonl)
so the run can be audited request by request.

With WAF_TEST_UPSTREAM (e.g. http://httpbin:80, a local container) an allowed request is
forwarded there unchanged (same method, request target, headers and body) and the origin's
response is returned, so the model can sit in front of a real web application.
"""

import http.client
import json
import os
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool

from ml.ml_api import load_gen3_model

MODEL, ERR = load_gen3_model()
THRESHOLD = float(os.environ.get("WAF_TEST_THRESHOLD", MODEL.threshold if MODEL else 0.5))
LOG_PATH = os.environ.get("WAF_TEST_LOG", os.path.join(os.path.dirname(__file__), "decisions.jsonl"))
UPSTREAM = os.environ.get("WAF_TEST_UPSTREAM", "").rstrip("/")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade",
              "content-length", "host"}
app = FastAPI(title="WAF Gen 3 detection test harness")


def forward(method, target, headers, body):
    """Send the request unchanged to WAF_TEST_UPSTREAM; (status, headers, body) of its response."""
    up = urlsplit(UPSTREAM)
    conn = http.client.HTTPConnection(up.hostname, up.port or 80, timeout=30)
    try:
        sent = {k: v for k, v in headers if k.lower() not in HOP_BY_HOP}
        sent["Host"] = up.netloc
        conn.request(method, target, body=body or None, headers=sent)
        r = conn.getresponse()
        return r.status, [(k, v) for k, v in r.getheaders() if k.lower() not in HOP_BY_HOP], r.read()
    finally:
        conn.close()


async def origin(request, url, raw):
    if not UPSTREAM:
        return PlainTextResponse("origin ok", status_code=200)
    try:
        status, headers, body = await run_in_threadpool(forward, request.method, url, request.headers.items(), raw)
    except Exception as exc:  # an unreachable origin is a 502, never a block
        return PlainTextResponse(f"origin error: {type(exc).__name__}", status_code=502)
    response = Response(content=body, status_code=status)
    for k, v in headers:
        response.headers.append(k, v)
    return response


@app.get("/healthz")
def healthz():
    return {"model_loaded": MODEL is not None, "runtime": getattr(MODEL, "runtime", None),
            "threshold": THRESHOLD, "error": ERR}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gate(full_path: str, request: Request):
    """Score the request; 403 = model flags an attack, otherwise the origin's answer (stub: 200 "origin ok")."""
    raw = await request.body()
    try:
        body = raw.decode("utf-8", "replace")
    except Exception:
        body = ""
    # The request target as sent: request.url.path is percent-decoded (%2F -> /), while production
    # scores the raw target from the nginx log's $request. 162 of 162,184 open-appsec requests
    # (paths with %2F or ;) scored differently before this.
    raw_path = request.scope.get("raw_path")
    # (some servers put the query in raw_path too, against the ASGI spec)
    path = raw_path.decode("latin-1").split("?", 1)[0] if raw_path else request.url.path
    url = path + (("?" + request.url.query) if request.url.query else "")
    if MODEL is None:
        return PlainTextResponse("model unavailable", status_code=503)
    try:
        score = MODEL.score_request(method=request.method, url=url, body=body)
    except Exception as exc:
        # Fail open, and record it, so a scoring crash never looks like a block.
        score = 0.0
        _log(request.method, url, len(raw), None, f"{type(exc).__name__}: {exc}")
        return await origin(request, url, raw)
    blocked = score >= THRESHOLD
    _log(request.method, url, len(raw), score, None)
    if blocked:
        return JSONResponse({"blocked": True, "score": round(score, 4)}, status_code=403)
    return await origin(request, url, raw)


def _log(method, url, body_len, score, error):
    rec = {"t": round(time.time(), 3), "method": method, "url": url[:800], "body_len": body_len,
           "score": score, "blocked": bool(score is not None and score >= THRESHOLD), "error": error}
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
