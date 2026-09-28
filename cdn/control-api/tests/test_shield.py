"""OTP / CAPTCHA shield: every method is gated (not only GET), and shield
events are queued for the dashboard. Runs against an in-memory Redis stand-in;
no network, no real Redis.

    cd cdn/control-api && python -m pytest tests -q
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import captcha_engine  # noqa: E402
import otp_engine  # noqa: E402
import shield_events  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv, self.lists = {}, {}

    def ping(self):
        return True

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v):
        self.kv[k] = v

    def setex(self, k, _ttl, v):
        self.kv[k] = v

    def delete(self, k):
        self.kv.pop(k, None)

    def ttl(self, _k):
        return 300

    def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]

    def expire(self, *_a):
        return True

    def lpush(self, k, v):
        self.lists.setdefault(k, []).insert(0, v)

    def ltrim(self, k, start, end):
        self.lists[k] = self.lists.get(k, [])[start:end + 1]

    def pipeline(self):
        return _Pipe(self)


class _Pipe:
    def __init__(self, r):
        self.r, self.ops = r, []

    def lpush(self, *a):
        self.ops.append(("lpush", a))

    def ltrim(self, *a):
        self.ops.append(("ltrim", a))

    def execute(self):
        for name, args in self.ops:
            getattr(self.r, name)(*args)


HOST = "shop.example.com"
ORIGIN = "origin-1"


@pytest.fixture()
def redis_(monkeypatch):
    r = FakeRedis()
    for module in (captcha_engine, otp_engine):
        monkeypatch.setattr(module, "_redis", lambda r=r: r)

    async def no_ml(_request):
        return "pass"

    monkeypatch.setattr(otp_engine, "ml_access_decision", no_ml)
    return r


@pytest.fixture()
def sent(monkeypatch):
    codes = []
    monkeypatch.setattr(otp_engine, "send_otp_email", lambda to, code: codes.append((to, code)) or True)
    return codes


@pytest.fixture()
def client():
    app = FastAPI()

    @app.api_route("/api/shield/access", methods=["GET", "POST"])
    async def access(request: Request):
        return await otp_engine.shield_access(request)

    @app.post("/cdn-cgi/otp/request")
    async def req(request: Request, payload: otp_engine.OtpRequestPayload):
        return await otp_engine.request_code(request, payload)

    @app.post("/cdn-cgi/otp/verify")
    async def ver(request: Request, payload: otp_engine.OtpVerifyPayload):
        return await otp_engine.verify_code(request, payload)

    return TestClient(app)


def enable(r, kind):
    key = f"waf:{kind}:domain:{HOST}"
    r.set(key, json.dumps({"enabled": True, "origin_id": ORIGIN, "login_paths": ["/login*"]}))


def check(client, method, path="/login", cookie=""):
    headers = {"X-Original-Method": method, "X-Original-URI": path, "X-Original-Host": HOST,
               "X-Original-IP": "198.51.100.7", "X-Original-User-Agent": "pytest"}
    if cookie:
        headers["Cookie"] = cookie
    return client.get("/api/shield/access", headers=headers)


def events(r):
    return [json.loads(x) for x in r.lists.get(shield_events.EVENTS_KEY, [])][::-1]


@pytest.mark.parametrize("kind", ["otp", "captcha"])
def test_get_without_clearance_gets_the_challenge_page(client, redis_, kind):
    enable(redis_, kind)
    resp = check(client, "GET")
    assert resp.status_code == 401
    assert resp.headers["X-Shield-Type"] == kind
    assert events(redis_)[-1]["event"] == "challenge_shown"


@pytest.mark.parametrize("kind", ["otp", "captcha"])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_other_methods_without_clearance_are_blocked(client, redis_, kind, method):
    # Before 2026-09-29 these returned 204 (allowed) -- a script could POST
    # credentials straight to the protected login path.
    enable(redis_, kind)
    resp = check(client, method)
    assert resp.status_code == 403
    assert resp.headers["X-Shield-Type"] == f"{kind}-required"
    ev = events(redis_)[-1]
    assert (ev["kind"], ev["event"], ev["origin_id"], ev["path"]) == (kind, "blocked_no_clearance", ORIGIN, "/login")


def test_options_preflight_is_not_gated(client, redis_):
    enable(redis_, "otp")
    assert check(client, "OPTIONS").status_code == 204


def test_unprotected_path_is_not_gated(client, redis_):
    enable(redis_, "otp")
    assert check(client, "POST", "/products").status_code == 204
    assert events(redis_) == []


def _request_code(client, email="alice@gmail.com"):
    return client.post("/cdn-cgi/otp/request", json={"host": HOST, "email": email},
                       headers={"User-Agent": "pytest"})


def _verify(client, challenge_id, code):
    return client.post("/cdn-cgi/otp/verify", json={"challenge_id": challenge_id, "code": code, "host": HOST},
                       headers={"User-Agent": "pytest"})


def test_full_flow_then_post_passes_with_cookie(client, redis_, sent):
    enable(redis_, "otp")
    challenge = _request_code(client).json()["challenge_id"]
    assert _verify(client, challenge, "000000" if sent[0][1] != "000000" else "111111").status_code == 400
    ok = _verify(client, challenge, sent[0][1])
    assert ok.status_code == 200
    cookie = f"{otp_engine.COOKIE_NAME}={ok.cookies[otp_engine.COOKIE_NAME]}"

    # Same client address and User-Agent as the verify call, so the cookie's
    # subnet/UA binding matches -- a POST now passes with clearance.
    headers = {"X-Original-Method": "POST", "X-Original-URI": "/login", "X-Original-Host": HOST,
               "User-Agent": "pytest", "X-Original-User-Agent": "pytest", "Cookie": cookie}
    assert client.get("/api/shield/access", headers=headers).status_code == 204

    names = [e["event"] for e in events(redis_)]
    assert names == ["otp_requested", "otp_wrong_code", "otp_verified"]
    assert all(e["email_masked"] == "al***@gmail.com" for e in events(redis_))
    assert all("alice@gmail.com" not in json.dumps(e) for e in events(redis_))


def test_rate_limit_and_send_failure_are_recorded(client, redis_, monkeypatch):
    enable(redis_, "otp")
    monkeypatch.setattr(otp_engine, "send_otp_email", lambda *_a: False)
    assert _request_code(client).status_code == 502
    for _ in range(3):
        _request_code(client)
    names = [e["event"] for e in events(redis_)]
    assert names[0] == "otp_send_failed"
    assert names[-1] == "otp_rate_limited"


def test_expired_code_is_recorded(client, redis_):
    enable(redis_, "otp")
    assert _verify(client, "no-such-challenge", "123456").status_code == 400
    assert events(redis_)[-1]["event"] == "otp_expired"


def test_event_queue_is_capped(redis_, monkeypatch):
    monkeypatch.setattr(shield_events, "MAX_QUEUED", 5)
    for i in range(12):
        shield_events.record(redis_, kind="otp", event=f"e{i}", host=HOST)
    names = [e["event"] for e in events(redis_)]
    assert names == ["e7", "e8", "e9", "e10", "e11"]


def test_mask_email():
    assert shield_events.mask_email("alice@gmail.com") == "al***@gmail.com"
    assert shield_events.mask_email("a@x.com") == "a***@x.com"
    assert shield_events.mask_email("not-an-email") == ""


def test_captcha_cookie_for_a_dotted_host_validates(redis_, monkeypatch):
    # Regression: split(".", 2) cut "shop.example.com" at its first dot, so no
    # clearance cookie ever validated and visitors looped on the challenge.
    import hashlib, hmac, time
    from starlette.requests import Request as StarletteRequest

    expiry = str(int(time.time()) + 600)
    ua = "pytest"
    message = "\x1f".join([captcha_engine.subnet_identity("198.51.100.7"), ua, HOST, expiry])
    sig = hmac.new(captcha_engine.HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    headers = [(b"cookie", f"{captcha_engine.COOKIE_NAME}={expiry}.{HOST}.{sig}".encode()),
               (b"x-original-ip", b"198.51.100.7"), (b"x-original-user-agent", ua.encode())]
    request = StarletteRequest({"type": "http", "headers": headers, "method": "GET", "path": "/"})
    assert captcha_engine._cookie_valid(request, HOST)
    tampered = [(b"cookie", f"{captcha_engine.COOKIE_NAME}={expiry}.evil.example.com.{sig}".encode())] + headers[1:]
    assert not captcha_engine._cookie_valid(StarletteRequest({"type": "http", "headers": tampered, "method": "GET", "path": "/"}), HOST)
