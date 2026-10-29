"""Image CAPTCHA on top of the proof of work, and the clearance cookie's
lifetime attributes. Same in-memory Redis stand-in as test_shield.py.

    cd cdn/control-api && python -m pytest tests -q
"""
import base64
import hashlib
import io
import json
import re
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))

import captcha_engine  # noqa: E402
from test_shield import HOST, ORIGIN, FakeRedis  # noqa: E402


class ScriptRedis(FakeRedis):
    """Adds what verify_challenge needs: the GET+DEL script and setex TTLs."""

    def setex(self, k, ttl, v):
        self.kv[k] = v
        self.ttls[k] = ttl

    def eval(self, _script, _numkeys, key):
        return self.kv.pop(key, None)


@pytest.fixture()
def redis_(monkeypatch):
    r = ScriptRedis()
    monkeypatch.setattr(captcha_engine, "_redis", lambda: r)
    monkeypatch.setattr(captcha_engine, "_last_known", {})
    return r


@pytest.fixture()
def app_client():
    app = FastAPI()

    @app.get("/cdn-cgi/challenge")
    async def challenge(request: Request):
        return await captcha_engine.issue_challenge(request)

    @app.post("/cdn-cgi/challenge/verify")
    async def verify(request: Request, payload: captcha_engine.ChallengeVerifyRequest):
        return await captcha_engine.verify_challenge(request, payload)

    return TestClient(app)


HEADERS = {"Host": HOST, "X-Original-IP": "198.51.100.7", "User-Agent": "pytest"}


def enable(r, **extra):
    config = {"enabled": True, "origin_id": ORIGIN, "login_paths": ["/login*"], "pow_difficulty": 2, **extra}
    r.set(f"waf:captcha:domain:{HOST}", json.dumps(config))
    r.hset(captcha_engine.HOSTMAP_KEY, HOST, ORIGIN)


def payload_of(html):
    return json.loads(re.search(r"JSON\.parse\('(\{.*?\})'\)", html).group(1))


def solve(challenge, valid=True):
    target = "0" * challenge["difficulty"]
    nonce = 0
    while hashlib.sha256((challenge["prefix"] + str(nonce)).encode()).hexdigest().startswith(target) != valid:
        nonce += 1
    return nonce


def verify(app_client, challenge, nonce, answer=None):
    body = {"challenge_id": challenge["challenge_id"], "nonce": nonce, "host": HOST}
    if answer is not None:
        body["answer"] = answer
    return app_client.post("/cdn-cgi/challenge/verify", headers=HEADERS, json=body)


@pytest.fixture()
def fixed_text(monkeypatch):
    monkeypatch.setattr(captcha_engine.secrets, "choice", lambda _seq: "K")
    return "KKKKK"


def test_without_image_the_page_and_flow_are_unchanged(app_client, redis_):
    enable(redis_)
    page = app_client.get("/cdn-cgi/challenge", headers=HEADERS).text
    challenge = payload_of(page)
    assert challenge["image"] is False and "<img" not in page
    assert redis_.ttls[f"waf:captcha:challenge:{challenge['challenge_id']}"] == captcha_engine.CHALLENGE_TTL
    resp = verify(app_client, challenge, solve(challenge))
    assert resp.status_code == 200 and resp.json() == {"success": True}


def test_clearance_cookie_lifetime_is_max_age_only(app_client, redis_):
    enable(redis_, clearance_ttl=900)
    challenge = payload_of(app_client.get("/cdn-cgi/challenge", headers=HEADERS).text)
    cookie = verify(app_client, challenge, solve(challenge)).headers["set-cookie"]
    assert "Max-Age=900" in cookie
    # Expires used to be built from the absolute expiry read as a delta, which
    # put it decades ahead.
    assert "expires" not in cookie.lower()


def test_image_challenge_shows_a_png_outside_the_script(app_client, redis_):
    enable(redis_, image_captcha=True)
    page = app_client.get("/cdn-cgi/challenge", headers=HEADERS).text
    challenge = payload_of(page)
    assert challenge["image"] is True
    src = re.search(r'<img id="captcha-image" src="data:image/png;base64,([A-Za-z0-9+/=]+)"', page).group(1)
    assert Image.open(io.BytesIO(base64.b64decode(src))).size == captcha_engine.IMAGE_SIZE
    assert "data:image" not in page[page.index("<script>"):]
    record = json.loads(redis_.kv[f"waf:captcha:challenge:{challenge['challenge_id']}"])
    assert "answer_digest" in record and "KKKKK" not in json.dumps(record)
    assert redis_.ttls[f"waf:captcha:challenge:{challenge['challenge_id']}"] == captcha_engine.IMAGE_CHALLENGE_TTL


def test_image_text_is_accepted_whatever_its_case_and_spacing(app_client, redis_, fixed_text):
    enable(redis_, image_captcha=True)
    challenge = payload_of(app_client.get("/cdn-cgi/challenge", headers=HEADERS).text)
    resp = verify(app_client, challenge, solve(challenge), answer=" kk kKk ")
    assert resp.status_code == 200 and "waf_clearance=" in resp.headers["set-cookie"]


@pytest.mark.parametrize("answer", [None, "", "KKKKX"])
def test_wrong_or_missing_text_is_refused_and_burns_the_challenge(app_client, redis_, fixed_text, answer):
    enable(redis_, image_captcha=True)
    challenge = payload_of(app_client.get("/cdn-cgi/challenge", headers=HEADERS).text)
    nonce = solve(challenge)
    resp = verify(app_client, challenge, nonce, answer=answer)
    assert resp.status_code == 400 and resp.json()["error"] == "invalid answer"
    assert "set-cookie" not in resp.headers
    retry = verify(app_client, challenge, nonce, answer=fixed_text)
    assert retry.status_code == 400 and retry.json()["error"] == "challenge expired"


def test_right_text_without_the_proof_of_work_is_refused(app_client, redis_, fixed_text):
    enable(redis_, image_captcha=True)
    challenge = payload_of(app_client.get("/cdn-cgi/challenge", headers=HEADERS).text)
    resp = verify(app_client, challenge, solve(challenge, valid=False), answer=fixed_text)
    assert resp.status_code == 400 and resp.json()["error"] == "invalid proof"


def test_answer_from_one_challenge_does_not_fit_another():
    assert captcha_engine._answer_digest("a", "KKKKK") != captcha_engine._answer_digest("b", "KKKKK")
    assert captcha_engine._answer_digest("a", "k kkkk") == captcha_engine._answer_digest("a", "KKKKK")


def test_images_differ_for_the_same_text():
    assert captcha_engine._captcha_png("ABCDE") != captcha_engine._captcha_png("ABCDE")
