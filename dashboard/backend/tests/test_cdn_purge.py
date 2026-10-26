"""POST /api/cdn/purge queues a purge for the caller's own verified site
(services/cdn_purge.py); the edges pull it from control-api. Before this the
endpoint answered 501 (audit H13)."""
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import auth as auth_module, cdn as cdn_module
from services import cdn_purge
from services.dynamodb_service import DynamoDBService
from services.rate_limiter import limiter
from tests.helpers.seed import seed_domain, seed_origin, uid


@pytest.fixture()
def client():
    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(auth_module.router)
    app.include_router(cdn_module.router)
    return TestClient(app)


@pytest.fixture()
def site(client, register_user, auth_header):
    register_user(email="first-admin@example.com", username="first_admin")  # first user is admin
    owner = register_user(email="owner@example.com", username="owner")
    stranger = register_user(email="stranger@example.com", username="stranger")
    db = DynamoDBService()
    origin = seed_origin(db, {"id": uid("o-shop"), "admin_user_id": owner["user"]["user_id"], "status": "active", "label": "shop"})
    seed_domain(db, {"origin_id": origin["id"], "domain_name": "shop.example.com", "dns_verified": True})
    seed_domain(db, {"origin_id": origin["id"], "domain_name": "pending.example.com", "dns_verified": False})
    return {"owner": auth_header(owner["access_token"]), "stranger": auth_header(stranger["access_token"])}


def _purge(client, headers, **body):
    client.cookies.clear()
    return client.post("/api/cdn/purge", json=body, headers=headers)


def _jobs():
    return cdn_purge._redis_client().zrange(cdn_purge.JOBS_KEY, 0, -1)


def test_owner_purges_a_page_and_the_whole_site(client, site):
    r = _purge(client, site["owner"], host="Shop.Example.com", path="/pricing?utm=x")
    assert r.status_code == 200, r.text
    assert r.json() == {"job_id": 1, "host": "shop.example.com", "path": "/pricing"}
    r = _purge(client, site["owner"], host="shop.example.com")
    assert r.json()["path"] == "/*"
    assert _jobs() == ["1\tshop.example.com\t/pricing", "2\tshop.example.com\t/*"]


@pytest.mark.parametrize("body, code", [
    ({"host": "shop.example.com", "path": "pricing"}, 400),
    ({"host": "shop.example.com", "path": "/a*b"}, 400),
    ({"host": "shop.example.com", "path": "/a b"}, 400),
    ({"host": "bad host", "path": "/"}, 400),
    ({"host": "pending.example.com", "path": "/"}, 404),   # not verified
    ({"host": "nobody.example.com", "path": "/"}, 404),
])
def test_bad_requests_queue_nothing(client, site, body, code):
    assert _purge(client, site["owner"], **body).status_code == code
    assert _jobs() == []


def test_someone_elses_site_is_refused(client, site):
    assert _purge(client, site["stranger"], host="shop.example.com", path="/").status_code == 403
    assert _jobs() == []


def test_status_shows_which_edges_applied_it(client, site):
    job = _purge(client, site["owner"], host="shop.example.com", path="/").json()["job_id"]
    now = int(time.time())
    cdn_purge._redis_client().hset(cdn_purge.ACKS_KEY, mapping={"10.88.0.2": f"{job}:{now}", "10.88.0.3": f"0:{now - 600}"})
    client.cookies.clear()
    edges = client.get(f"/api/cdn/purge/{job}", headers=site["owner"]).json()["edges"]
    assert edges["edge-th"] == {"applied": True, "last_poll": now, "polling": True}
    assert edges["edge-asia"]["applied"] is False and edges["edge-asia"]["polling"] is False
