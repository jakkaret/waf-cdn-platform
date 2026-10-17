"""Support tickets and time-limited support access (docs/tickets/support-access.md)."""
import pytest
from fastapi.testclient import TestClient

from api import support as support_module
from db import pool
from tests.helpers.seed import make_origin


@pytest.fixture()
def sc(app):
    app.include_router(support_module.router)
    return TestClient(app)


@pytest.fixture()
def people(sc, register_user):
    """owner (origin admin), other (unrelated user), staff (platform admin)."""
    def mk(email, role):
        r = register_user(email=email, username=email.split("@")[0])
        pool.exec_("UPDATE users SET role = %s WHERE user_id = %s", (role, r["user"]["user_id"]))
        return {"id": r["user"]["user_id"], "h": {"Authorization": f"Bearer {r['access_token']}"}, "user": r["user"]}
    owner, other, staff = mk("own@example.com", "viewer"), mk("oth@example.com", "viewer"), mk("sup@example.com", "admin")
    origin = make_origin({"user_id": owner["id"]}, label="shop")
    other_origin = make_origin({"user_id": other["id"]}, label="other-shop")
    return {"owner": owner, "other": other, "staff": staff, "origin": origin["id"], "other_origin": other_origin["id"]}


def _open(sc, p, who="owner", origin=None):
    return sc.post("/api/support/tickets", headers=p[who]["h"],
                   json={"origin_id": origin or p["origin"], "subject": "site down", "message": "help"})


def _grant(sc, p, tid, level="viewer", hours=24, confirm=False, who="owner"):
    return sc.post(f"/api/support/tickets/{tid}/grant", headers=p[who]["h"],
                   json={"level": level, "hours": hours, "confirm_edit": confirm})


def test_only_origin_admin_opens_ticket(sc, people):
    assert _open(sc, people).status_code == 201
    assert _open(sc, people, who="other").status_code == 404
    assert _open(sc, people, who="staff").status_code == 404


def test_ticket_visibility(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    assert sc.get(f"/api/support/tickets/{tid}", headers=people["owner"]["h"]).status_code == 200
    assert sc.get(f"/api/support/tickets/{tid}", headers=people["staff"]["h"]).status_code == 200
    assert sc.get(f"/api/support/tickets/{tid}", headers=people["other"]["h"]).status_code == 404
    assert [t["ticket_id"] for t in sc.get("/api/support/tickets", headers=people["other"]["h"]).json()["tickets"]] == []
    assert tid in [t["ticket_id"] for t in sc.get("/api/support/tickets", headers=people["staff"]["h"]).json()["tickets"]]


def test_staff_has_no_origin_access_without_grant(sc, people):
    _open(sc, people)
    assert sc.get(f"/api/origins/{people['origin']}", headers=people["staff"]["h"]).status_code == 403


def test_viewer_grant_reads_but_cannot_edit(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    assert _grant(sc, people, tid).status_code == 201
    h = people["staff"]["h"]
    assert sc.get(f"/api/origins/{people['origin']}", headers=h).status_code == 200
    assert sc.put(f"/api/origins/{people['origin']}", headers=h, json={"label": "x"}).status_code == 403


def test_editor_grant_needs_confirmation_and_allows_edit(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    assert _grant(sc, people, tid, level="editor").status_code == 400
    assert _grant(sc, people, tid, level="editor", confirm=True).status_code == 201
    r = sc.put(f"/api/origins/{people['origin']}", headers=people["staff"]["h"], json={"label": "fixed-by-support"})
    assert r.status_code == 200, r.text


def test_grant_never_gives_ownership_actions(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid, level="editor", confirm=True)
    h = people["staff"]["h"]
    assert sc.get(f"/api/origins/{people['origin']}/viewers", headers=h).status_code == 403
    assert sc.delete(f"/api/origins/{people['origin']}", headers=h).status_code == 403


def test_grant_is_limited_to_its_origin(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)
    assert sc.get(f"/api/origins/{people['other_origin']}", headers=people["staff"]["h"]).status_code == 403


def test_non_staff_cannot_use_a_grant(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)
    assert sc.get(f"/api/origins/{people['origin']}", headers=people["other"]["h"]).status_code == 403


def test_only_origin_admin_grants_and_revokes(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    assert _grant(sc, people, tid, who="staff").status_code == 403
    _grant(sc, people, tid)
    assert sc.delete(f"/api/support/tickets/{tid}/grant", headers=people["staff"]["h"]).status_code == 403
    assert sc.delete(f"/api/support/tickets/{tid}/grant", headers=people["owner"]["h"]).json()["revoked"] == 1
    assert sc.get(f"/api/origins/{people['origin']}", headers=people["staff"]["h"]).status_code == 403


def test_expired_grant_stops_working(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)
    pool.exec_("UPDATE support_grants SET expires_at = now() - interval '1 minute' WHERE ticket_id = %s", (tid,))
    assert sc.get(f"/api/origins/{people['origin']}", headers=people["staff"]["h"]).status_code == 403


def test_closing_ticket_revokes_access(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)
    assert sc.post(f"/api/support/tickets/{tid}/close", headers=people["staff"]["h"]).status_code == 200
    assert sc.get(f"/api/origins/{people['origin']}", headers=people["staff"]["h"]).status_code == 403
    assert _grant(sc, people, tid).status_code == 400
    r = sc.post(f"/api/support/tickets/{tid}/messages", headers=people["owner"]["h"], json={"body": "more"})
    assert r.status_code == 400


def test_hours_bounds(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    assert _grant(sc, people, tid, hours=0).status_code == 422
    assert _grant(sc, people, tid, hours=73).status_code == 422


def test_access_is_logged_for_the_owner(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid, level="editor", confirm=True)
    h = people["staff"]["h"]
    sc.get(f"/api/origins/{people['origin']}", headers=h)
    sc.get(f"/api/origins/{people['origin']}", headers=h)  # folded into one read entry
    sc.put(f"/api/origins/{people['origin']}", headers=h, json={"label": "y"})
    log = sc.get(f"/api/support/tickets/{tid}", headers=people["owner"]["h"]).json()["access_log"]
    kinds = sorted(e["kind"] for e in log)
    assert kinds.count("read") == 1 and kinds.count("edit") >= 1
    assert all(e["staff_id"] == people["staff"]["id"] for e in log)


def test_messages_mark_support_replies(sc, people):
    tid = _open(sc, people).json()["ticket_id"]
    sc.post(f"/api/support/tickets/{tid}/messages", headers=people["staff"]["h"], json={"body": "looking"})
    msgs = sc.get(f"/api/support/tickets/{tid}", headers=people["owner"]["h"]).json()["messages"]
    assert [m["is_support"] for m in msgs] == [False, True]


def test_admin_scope_follows_real_grants(sc, people):
    """End to end against Postgres: the origin's verified host leaves the
    admin's blocked list while a grant is active, and returns when it ends."""
    from services import tenant_service as ts
    pool.exec_("INSERT INTO domains (domain_name, origin_id, dns_verified, verification_token) VALUES (%s, %s, true, 't')",
               ("shop-scope.example", people["origin"]))
    ts.invalidate_admin_scope_cache()
    assert ts.build_tenant_origin_filter("shop-scope.example", [], True) == "1=0"
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)
    assert ts.build_tenant_origin_filter("shop-scope.example", [], True) == "(host = 'shop-scope.example')"
    sc.post(f"/api/support/tickets/{tid}/close", headers=people["owner"]["h"])
    assert ts.build_tenant_origin_filter("shop-scope.example", [], True) == "1=0"


def test_editor_opens_ticket_but_only_owner_grants(sc, people):
    """Owner > Editor > Viewer (2026-10-17): an editor works the ticket, but who
    may enter the origin is the owner's call."""
    pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, 'editor')",
               (people["origin"], people["other"]["id"]))
    ed = people["other"]["h"]
    r = sc.post("/api/support/tickets", headers=ed, json={"origin_id": people["origin"], "subject": "s", "message": "m"})
    assert r.status_code == 201
    tid = r.json()["ticket_id"]
    detail = sc.get(f"/api/support/tickets/{tid}", headers=ed).json()
    assert detail["can_grant"] is False
    g = sc.post(f"/api/support/tickets/{tid}/grant", headers=ed, json={"level": "viewer", "hours": 1})
    assert g.status_code == 403 and "owner" in g.json()["detail"].lower()
    assert _grant(sc, people, tid).status_code == 201


def test_one_tenants_grant_never_opens_another_tenants_host(sc, people):
    """A granting tenant that also lists another tenant's host (an unverified
    BYO row is enough) must not make that host visible to support."""
    from services import tenant_service as ts
    pool.exec_("INSERT INTO domains (domain_name, origin_id, dns_verified, verification_token) VALUES (%s, %s, true, 't')",
               ("victim-host.example", people["other_origin"]))
    pool.exec_("INSERT INTO domains (domain_name, origin_id, dns_verified, verification_token) VALUES (%s, %s, false, 't2')",
               ("victim-host.example", people["origin"]))
    tid = _open(sc, people).json()["ticket_id"]
    _grant(sc, people, tid)  # only the owner's origin is granted
    ts.invalidate_admin_scope_cache()
    assert ts.build_tenant_origin_filter("victim-host.example", [], True) == "1=0"
    assert "'victim-host.example'" in ts.build_tenant_origin_filter("ALL", [], True)
