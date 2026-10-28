"""
GET /api/origins/overview (services/origin_overview.py) feeds the Origins
list: 24 h requests/blocked, the five protections and live domains for each
origin the caller can see. It must never show an origin, or traffic, that
the per-origin pages would not: other tenants' origins are absent, and
traffic is counted only for an origin's DNS-verified hosts.
"""
from fastapi.testclient import TestClient

from services import origin_overview


class _FakeCH:
    """Answers the overview's one GROUP BY host query from a fixed table and
    records which hosts it was asked about."""
    connected = True

    def __init__(self, rows):
        self.rows = rows
        self.asked = None
        self.client = self

    def query(self, sql, parameters=None):
        self.asked = list(parameters["hosts"])
        wanted = set(self.asked)

        class _Res:
            result_rows = [r for r in self.rows if r[0] in wanted]
        return _Res()


def _origin(client, headers, label, ip):
    resp = client.post("/api/origins", json={"label": label, "ip": ip, "port": 443}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_overview_is_not_read_as_an_origin_id(client: TestClient, register_user, auth_header):
    u = register_user(email="ov0@example.com", username="ov0")
    resp = client.get("/api/origins/overview", headers=auth_header(u["access_token"]))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"origins": []}


def test_counts_only_verified_hosts_of_the_callers_origins(client: TestClient, register_user, auth_header, db, monkeypatch):
    a = register_user(email="ova@example.com", username="ova")
    b = register_user(email="ovb@example.com", username="ovb")
    ha, hb = auth_header(a["access_token"]), auth_header(b["access_token"])
    oa = _origin(client, ha, "shop-a.example.com", "203.0.113.21")
    ob = _origin(client, hb, "shop-b.example.com", "203.0.113.22")
    db.create_domain({"origin_id": oa["id"], "domain_name": "shop-a.example.com", "dns_verified": True})
    db.create_domain({"origin_id": oa["id"], "domain_name": "pending-a.example.com", "dns_verified": False})
    db.create_domain({"origin_id": ob["id"], "domain_name": "shop-b.example.com", "dns_verified": True})

    fake = _FakeCH([
        ("shop-a.example.com", 120, 7),
        ("pending-a.example.com", 999, 999),  # not verified: must not count
        ("shop-b.example.com", 50, 5),        # another tenant's host
    ])
    monkeypatch.setattr(origin_overview, "_CH", fake)

    rows = client.get("/api/origins/overview", headers=ha).json()["origins"]
    assert [r["origin_id"] for r in rows] == [oa["id"]]
    row = rows[0]
    assert (row["requests_24h"], row["blocked_24h"]) == (120, 7)
    assert fake.asked == ["shop-a.example.com"]
    assert row["domains"] == {"total": 2, "verified": 1}
    assert set(row["protection"]) == {"waf", "ml", "ip", "rate", "shield"}
    assert row["protection"]["ml"]["mode"] == "log"
    assert row["protection"]["ip"] == {"block": 0, "allow": 0}

    rows_b = client.get("/api/origins/overview", headers=hb).json()["origins"]
    assert [r["origin_id"] for r in rows_b] == [ob["id"]]
    assert rows_b[0]["blocked_24h"] == 5


def test_a_viewer_sees_the_shared_origin_and_nothing_else(client: TestClient, register_user, auth_header, db, monkeypatch):
    owner = register_user(email="ovo@example.com", username="ovo")
    viewer = register_user(email="ovv@example.com", username="ovv")
    ho, hv = auth_header(owner["access_token"]), auth_header(viewer["access_token"])
    shared = _origin(client, ho, "shared.example.com", "203.0.113.31")
    _origin(client, ho, "private.example.com", "203.0.113.32")
    resp = client.post(f"/api/origins/{shared['id']}/viewers", json={"email": "ovv@example.com"}, headers=ho)
    assert resp.status_code == 200, resp.text
    db.create_domain({"origin_id": shared["id"], "domain_name": "shared.example.com", "dns_verified": True})
    monkeypatch.setattr(origin_overview, "_CH", _FakeCH([("shared.example.com", 10, 2)]))

    rows = client.get("/api/origins/overview", headers=hv).json()["origins"]
    assert [r["origin_id"] for r in rows] == [shared["id"]]
    assert rows[0]["blocked_24h"] == 2
    # Reading the overview grants nothing: the viewer still cannot edit.
    assert client.put(f"/api/origins/{shared['id']}", json={"label": "x"}, headers=hv).status_code == 403


def test_unreachable_log_store_leaves_traffic_unknown_not_zero(client: TestClient, register_user, auth_header, db):
    u = register_user(email="ovc@example.com", username="ovc")
    h = auth_header(u["access_token"])
    o = _origin(client, h, "down.example.com", "203.0.113.41")
    db.create_domain({"origin_id": o["id"], "domain_name": "down.example.com", "dns_verified": True})
    # conftest's default store is not connected.
    row = client.get("/api/origins/overview", headers=h).json()["origins"][0]
    assert row["requests_24h"] is None and row["blocked_24h"] is None
    assert row["protection"]["waf"]["custom_rules"] == 0


def test_an_origin_without_verified_hosts_counts_nothing(client: TestClient, register_user, auth_header, monkeypatch):
    u = register_user(email="ovd@example.com", username="ovd")
    h = auth_header(u["access_token"])
    _origin(client, h, "new.example.com", "203.0.113.51")
    fake = _FakeCH([("new.example.com", 5, 5)])
    monkeypatch.setattr(origin_overview, "_CH", fake)
    row = client.get("/api/origins/overview", headers=h).json()["origins"][0]
    assert (row["requests_24h"], row["blocked_24h"]) == (0, 0)
    assert fake.asked is None  # no host to ask about, no query at all


def test_requires_login(client: TestClient):
    assert client.get("/api/origins/overview").status_code in (401, 403)
