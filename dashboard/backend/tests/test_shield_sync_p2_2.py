"""P2.2 (C1, H39, N11, H36, H37): CAPTCHA/OTP config follows a domain to its
current owner for the domain's whole life.

control-api reads waf:<kind>:domain:<host> and applies it only while the
host's owner in waf:shield:hostmap is the key's origin_id
(cdn/control-api/tests/test_shield_phase2.py covers that side). Here: the
dashboard keeps both in line with the database (services/shield_sync.py).
"""
import asyncio
import json

import pytest
import redis

import api.domains as domains_module
from services import shield_sync
from tests.helpers.seed import make_domain, make_origin

CAPTCHA = {"enabled": True, "engine": "native", "login_paths": ["/login*"], "clearance_ttl": 3600,
           "bypass_ips": [], "pow_difficulty": 3, "mode": "enforce", "exclude_paths": []}
OTP = {"enabled": True, "login_paths": ["/login*"], "clearance_ttl": 3600, "bypass_ips": [], "code_length": 6,
       "code_ttl": 300, "channel": "email", "mode": "enforce", "exclude_paths": [], "access_mode": "open",
       "allowed_emails": []}


@pytest.fixture()
def shield_client(app, client):
    app.include_router(domains_module.origins_domains_router)
    return client


@pytest.fixture()
def owner(register_user, auth_header):
    register_user(email="admin-first@example.com", username="admin_first")  # first user = admin
    body = register_user(email="owner@example.com", username="owner_user")
    return {"user_id": body["user"]["user_id"], "headers": auth_header(body["access_token"])}


def _r():
    return redis.Redis(decode_responses=True)


def _key(kind, host):
    return _r().get(f"waf:{kind}:domain:{host}")


def _domain_keys():
    return sorted(_r().scan_iter(match="waf:*:domain:*"))


def _enable(client, owner, origin_id, kind, body):
    resp = client.put(f"/api/origins/{origin_id}/{kind}", headers=owner["headers"], json=body)
    assert resp.status_code == 200, resp.text


def test_otp_switched_on_before_a_second_domain_is_verified_covers_it(shield_client, owner, db):
    origin = make_origin(owner, db=db, status="active")
    make_domain(origin, "one.example.com", db=db)
    second = make_domain(origin, "two.example.com", db=db, dns_verified=False)
    _enable(shield_client, owner, origin["id"], "otp", OTP)
    _enable(shield_client, owner, origin["id"], "captcha", CAPTCHA)
    assert _key("otp", "two.example.com") is None

    db.update_domain(second["id"], {"dns_verified": True})
    asyncio.run(domains_module.after_domain_verified(origin["id"], "two.example.com"))

    for kind in ("otp", "captcha"):
        value = json.loads(_key(kind, "two.example.com"))
        assert (value["enabled"], value["origin_id"], value["domain"]) == (True, origin["id"], "two.example.com")
    assert _r().hget(shield_sync.HOSTMAP_KEY, "two.example.com") == origin["id"]


def test_deleting_a_domain_leaves_no_key(shield_client, owner, db):
    origin = make_origin(owner, db=db, status="active")
    make_domain(origin, "keep.example.com", db=db)
    gone = make_domain(origin, "gone.example.com", db=db)
    _enable(shield_client, owner, origin["id"], "otp", OTP)
    _enable(shield_client, owner, origin["id"], "captcha", CAPTCHA)
    assert _key("otp", "gone.example.com")

    resp = shield_client.delete(f"/api/origins/{origin['id']}/domains/{gone['id']}", headers=owner["headers"])
    assert resp.status_code == 200, resp.text

    assert _domain_keys() == ["waf:captcha:domain:keep.example.com", "waf:otp:domain:keep.example.com"]
    assert _r().hget(shield_sync.HOSTMAP_KEY, "gone.example.com") is None


def test_archiving_an_origin_removes_its_keys_and_restoring_brings_them_back(shield_client, owner, db):
    origin = make_origin(owner, db=db, status="active")
    make_domain(origin, "shop.example.com", db=db)
    _enable(shield_client, owner, origin["id"], "captcha", CAPTCHA)

    assert shield_client.delete(f"/api/origins/{origin['id']}", headers=owner["headers"]).status_code == 200
    assert _domain_keys() == []
    assert _r().hgetall(shield_sync.HOSTMAP_KEY) == {}

    assert shield_client.post(f"/api/origins/{origin['id']}/restore", headers=owner["headers"]).status_code == 200
    assert json.loads(_key("captcha", "shop.example.com"))["origin_id"] == origin["id"]


def test_new_owner_of_a_released_host_does_not_inherit_the_old_config(shield_client, owner, db, register_user, auth_header):
    old = make_origin(owner, db=db, status="active")
    domain = make_domain(old, "shared.example.com", db=db)
    _enable(shield_client, owner, old["id"], "otp", dict(OTP, access_mode="allowlist", allowed_emails=["boss@old.com"]))
    shield_client.delete(f"/api/origins/{old['id']}/domains/{domain['id']}", headers=owner["headers"])

    body = register_user(email="new@example.com", username="new_owner")
    new_owner = {"user_id": body["user"]["user_id"]}
    new = make_origin(new_owner, db=db, status="active")
    make_domain(new, "shared.example.com", db=db)
    shield_sync.reconcile(db)

    assert _key("otp", "shared.example.com") is None  # the new origin has no OTP settings of its own
    assert _r().hget(shield_sync.HOSTMAP_KEY, "shared.example.com") == new["id"]


def test_stale_key_is_swept_and_hostmap_rebuilt_by_the_worker_pass(owner, db):
    origin = make_origin(owner, db=db, status="active")
    make_domain(origin, "live.example.com", db=db)
    r = _r()
    r.set(f"waf:captcha:origin:{origin['id']}", json.dumps(dict(CAPTCHA, origin_id=origin["id"])))
    r.set("waf:captcha:domain:orphan.example.com", json.dumps(dict(CAPTCHA, origin_id="gone")))
    r.set("waf:otp:domain:orphan.example.com", json.dumps(dict(OTP, origin_id="gone")))
    r.hset(shield_sync.HOSTMAP_KEY, "orphan.example.com", "gone")

    summary = shield_sync.reconcile(db)

    assert _domain_keys() == ["waf:captcha:domain:live.example.com"]
    assert r.hgetall(shield_sync.HOSTMAP_KEY) == {"live.example.com": origin["id"]}
    assert summary == {"hosts": 1, "written": 1, "removed": 2}
    assert shield_sync.reconcile(db) == {"hosts": 1, "written": 0, "removed": 0}  # idempotent


def test_unverified_and_doubly_claimed_hosts_get_no_key(owner, db):
    a = make_origin(owner, db=db, status="active")
    b = make_origin(owner, db=db, status="active")
    make_domain(a, "pending.example.com", db=db, dns_verified=False)
    make_domain(a, "both.example.com", db=db)                            # a: verified BYO domain
    db.update_origin(b["id"], {"tunnel_domains": ["both.example.com"]})  # b: the same name as a tunnel host
    for origin in (a, b):
        _r().set(f"waf:captcha:origin:{origin['id']}", json.dumps(dict(CAPTCHA, origin_id=origin["id"])))

    shield_sync.reconcile(db)

    assert _domain_keys() == []
    assert _r().hgetall(shield_sync.HOSTMAP_KEY) == {}


def test_tunnel_hosts_of_the_origin_are_covered_too(shield_client, owner, db):
    origin = make_origin(owner, db=db, status="active")
    db.update_origin(origin["id"], {"tunnel_domains": ["app.example.com"]})
    _enable(shield_client, owner, origin["id"], "captcha", CAPTCHA)
    assert json.loads(_key("captcha", "app.example.com"))["origin_id"] == origin["id"]


def test_saving_drops_keys_of_hosts_the_origin_no_longer_has(owner, db):
    from services import captcha_config
    origin = make_origin(owner, db=db, status="active")
    captcha_config.save_origin_config(origin["id"], CAPTCHA, ["a.example.com", "b.example.com"])
    _r().set("waf:captcha:domain:other.example.com", json.dumps(dict(CAPTCHA, origin_id="someone-else")))
    captcha_config.save_origin_config(origin["id"], CAPTCHA, ["a.example.com"])
    assert _domain_keys() == ["waf:captcha:domain:a.example.com", "waf:captcha:domain:other.example.com"]


def test_deleting_a_user_removes_the_keys_of_the_origins_archived_with_them(shield_client, owner, db, register_user, auth_header):
    origin = make_origin(owner, db=db, status="active")
    make_domain(origin, "user-site.example.com", db=db)
    _enable(shield_client, owner, origin["id"], "captcha", CAPTCHA)
    admin = shield_client.post("/api/auth/login", json={"email": "admin-first@example.com", "password": "Sup3rSecret!"})
    headers = auth_header(admin.json()["access_token"])
    assert shield_client.delete(f"/api/auth/users/{owner['user_id']}", headers=headers).status_code == 200
    assert _domain_keys() == []
