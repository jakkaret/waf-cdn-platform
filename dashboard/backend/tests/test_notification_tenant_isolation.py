"""Real cross-tenant leak, reported live by the user (2026-09-22): a
brand-new account saw every other tenant's alerts in the notification
feed, and "mark all read" -- run live against this project's own
production data tonight -- silently marked ~5786 OTHER tenants' alerts
read. Root cause: waf_alerts' user_id has always been a hardcoded
"default-user" placeholder (services/telegram_listener.py, the real
writer), never a usable owner, and neither the read nor either write
branch filtered on anything at all.

The fix scopes both GET /notifications/feed and POST /notifications/mark-
read (both branches) by the alert's captured domain (Host header, now
stored as "domain") against the requesting user's own registered
domains -- exactly the shape this test proves with two real registered
users, each with their own real origin+domain, and alerts seeded under
each."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from services.rate_limiter import limiter
from api import auth as auth_module
from api import origins as origins_module
from api import domains as domains_module
from api import ai_summary as ai_summary_module


@pytest.fixture()
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(domains_module.origins_domains_router)
    test_app.include_router(ai_summary_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _create_origin_with_domain(client, token, auth_header, label, domain_name):
    h = auth_header(token)
    resp = client.post("/api/origins", json={"label": label, "ip": "203.0.113.50", "port": 8080}, headers=h)
    assert resp.status_code == 200, resp.text
    origin_id = resp.json()["id"]
    resp = client.post(f"/api/origins/{origin_id}/domains", json={"domain_name": domain_name}, headers=h)
    assert resp.status_code == 200, resp.text
    return origin_id


def _seed_alert(alert_id, domain, read=False):
    ai_summary_module.db.save_alert(
        user_id="default-user", alert_id=alert_id, ip="9.9.9.9", url="/wp-login.php",
        status="403", message="blocked", domain=domain,
    )
    if read:
        item = next(a for a in ai_summary_module.db.get_all_alerts(max_items=2000) if a["alert_id"] == alert_id)
        item["read"] = True


def test_a_user_sees_only_alerts_matching_their_own_domain(client, register_user, auth_header):
    register_user(email="decoy1@example.com", username="decoy1")  # consumes the first-user-becomes-admin slot
    user_a = register_user(email="tenant-a@example.com", username="tenant_a")
    user_b = register_user(email="tenant-b@example.com", username="tenant_b")
    _create_origin_with_domain(client, user_a["access_token"], auth_header, "origin-a", "tenant-a.waf-it-kku.online")
    _create_origin_with_domain(client, user_b["access_token"], auth_header, "origin-b", "tenant-b.waf-it-kku.online")

    _seed_alert("alert-a-1", "tenant-a.waf-it-kku.online")
    _seed_alert("alert-b-1", "tenant-b.waf-it-kku.online")

    resp = client.get("/api/ai/notifications/feed", headers=auth_header(user_a["access_token"]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    alert_ids = [n["alert_id"] for n in body["notifications"]]
    assert "alert-a-1" in alert_ids
    assert "alert-b-1" not in alert_ids
    assert body["unread_count"] == 1


def test_mark_all_read_never_touches_another_tenants_alerts(client, register_user, auth_header):
    register_user(email="decoy2@example.com", username="decoy2")  # consumes the first-user-becomes-admin slot
    user_a = register_user(email="tenant-a2@example.com", username="tenant_a2")
    user_b = register_user(email="tenant-b2@example.com", username="tenant_b2")
    _create_origin_with_domain(client, user_a["access_token"], auth_header, "origin-a2", "tenant-a2.waf-it-kku.online")
    _create_origin_with_domain(client, user_b["access_token"], auth_header, "origin-b2", "tenant-b2.waf-it-kku.online")

    _seed_alert("alert-a2-1", "tenant-a2.waf-it-kku.online")
    _seed_alert("alert-b2-1", "tenant-b2.waf-it-kku.online")

    resp = client.post("/api/ai/notifications/mark-read", json={}, headers=auth_header(user_a["access_token"]))
    assert resp.status_code == 200, resp.text

    all_alerts = {a["alert_id"]: a for a in ai_summary_module.db.get_all_alerts(max_items=2000)}
    assert all_alerts["alert-a2-1"]["read"] is True
    assert all_alerts["alert-b2-1"]["read"] is False


def test_a_user_cannot_mark_a_specific_alert_belonging_to_another_tenant(client, register_user, auth_header):
    register_user(email="decoy3@example.com", username="decoy3")  # consumes the first-user-becomes-admin slot
    user_a = register_user(email="tenant-a3@example.com", username="tenant_a3")
    user_b = register_user(email="tenant-b3@example.com", username="tenant_b3")
    _create_origin_with_domain(client, user_a["access_token"], auth_header, "origin-a3", "tenant-a3.waf-it-kku.online")
    _create_origin_with_domain(client, user_b["access_token"], auth_header, "origin-b3", "tenant-b3.waf-it-kku.online")

    _seed_alert("alert-b3-1", "tenant-b3.waf-it-kku.online")

    resp = client.post(
        "/api/ai/notifications/mark-read", json={"alert_id": "alert-b3-1"},
        headers=auth_header(user_a["access_token"]),
    )
    assert resp.status_code == 200, resp.text  # silent no-op, not an error/oracle

    all_alerts = {a["alert_id"]: a for a in ai_summary_module.db.get_all_alerts(max_items=2000)}
    assert all_alerts["alert-b3-1"]["read"] is False


def test_admin_sees_and_can_mark_every_tenants_alerts(client, register_user, auth_header):
    admin = register_user(email="admin4@example.com", username="admin4")  # first user = admin
    user_b = register_user(email="tenant-b4@example.com", username="tenant_b4")
    _create_origin_with_domain(client, user_b["access_token"], auth_header, "origin-b4", "tenant-b4.waf-it-kku.online")

    _seed_alert("alert-b4-1", "tenant-b4.waf-it-kku.online")

    resp = client.get("/api/ai/notifications/feed", headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200, resp.text
    assert "alert-b4-1" in [n["alert_id"] for n in resp.json()["notifications"]]

    resp = client.post("/api/ai/notifications/mark-read", json={}, headers=auth_header(admin["access_token"]))
    assert resp.status_code == 200, resp.text
    all_alerts = {a["alert_id"]: a for a in ai_summary_module.db.get_all_alerts(max_items=2000)}
    assert all_alerts["alert-b4-1"]["read"] is True


def test_an_alert_with_no_captured_domain_is_hidden_from_non_admins(client, register_user, auth_header):
    """Fail closed, not open -- an alert row predating this fix (or any
    future write that somehow lacks a domain) must never appear as
    "belongs to everyone" by falling through an empty-string match."""
    register_user(email="decoy5@example.com", username="decoy5")  # consumes the first-user-becomes-admin slot
    user_a = register_user(email="tenant-a5@example.com", username="tenant_a5")
    _create_origin_with_domain(client, user_a["access_token"], auth_header, "origin-a5", "tenant-a5.waf-it-kku.online")

    _seed_alert("alert-no-domain", "")

    resp = client.get("/api/ai/notifications/feed", headers=auth_header(user_a["access_token"]))
    assert resp.status_code == 200, resp.text
    assert "alert-no-domain" not in [n["alert_id"] for n in resp.json()["notifications"]]
