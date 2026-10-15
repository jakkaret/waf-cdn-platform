"""Phase 3: users, origins, members, domains, hostnames and SSL records on
PostgreSQL, and the dict shapes callers rely on."""
import uuid
from datetime import datetime

import pytest

from tests import pg_harness

pytestmark = [pytest.mark.pg,
              pytest.mark.skipif(not pg_harness.enabled(), reason="TEST_DATABASE_URL not set")]


@pytest.fixture(autouse=True)
def _fresh_pool():
    from db import pool
    pool.close_pool()   # use this test database's DATABASE_URL
    yield
    pool.close_pool()


@pytest.fixture()
def store():
    from services.pg_store import PgStore
    return PgStore()


def _users():
    from services.pg_store import PgUserRepository
    return PgUserRepository()


def _user(email=None, role="viewer"):
    return _users().create(email or f"u-{uuid.uuid4().hex[:8]}@example.com", "user",
                           "$argon2id$x", role, "local", None, None)


def _origin(store, owner_id, **fields):
    oid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + "Z"
    data = {"id": oid, "admin_user_id": owner_id, "label": "app", "ip": "203.0.113.5", "port": 8080,
            "status": fields.pop("status", "active"), "created_at": now, "updated_at": now, **fields}
    assert store.create_origin(data) is True
    return oid


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ------------------------------------------------------------------ users

def test_user_shape_and_lookups():
    users = _users()
    u = users.create("Mixed@Example.com", "mixed", "$argon2id$x", "admin", "local", None, None)
    assert set(u) >= {"user_id", "email", "username", "role", "password_hash", "auth_provider",
                      "share_threat_intel", "created_at", "last_login"}
    assert uuid.UUID(u["user_id"]) and u["role"] == "admin" and u["auth_provider"] == "local"
    _parse(u["created_at"]) and _parse(u["last_login"])
    assert u["created_at"].endswith("Z")
    assert users.get_by_email("mixed@example.COM")["user_id"] == u["user_id"]
    assert users.get_by_id("not-a-uuid") is None
    assert "telegram_chat_id" not in u and "avatar_url" not in u


def test_google_user_gets_an_identity_and_empty_password_hash():
    users = _users()
    g = users.create("g@example.com", "g", None, "viewer", "google", "sub-123", "https://img")
    assert g["password_hash"] == "" and g["provider_id"] == "sub-123" and g["avatar_url"] == "https://img"
    assert users.get_by_provider("google", "sub-123")["user_id"] == g["user_id"]
    assert users.get_by_provider("telegram", "sub-123") is None


def test_unknown_role_becomes_viewer_and_duplicates_are_value_errors():
    users = _users()
    assert users.create("r@example.com", "r", "$argon2id$x", "editor", "local", None, None)["role"] == "viewer"
    with pytest.raises(ValueError):
        users.create("R@example.com", "r2", "$argon2id$x", "viewer", "local", None, None)


def test_telegram_chat_connect_and_disconnect():
    users = _users()
    u = _user()
    assert users.set_field(u["user_id"], "telegram_chat_id", "555") is True
    assert [r["user_id"] for r in users.list_telegram_recipients()] == [u["user_id"]]
    users.set_field(u["user_id"], "telegram_chat_id", None)
    assert users.list_telegram_recipients() == []


def test_deleting_an_owner_archives_their_origins():
    from services.pg_store import PgStore
    store, users = PgStore(), _users()
    owner, other = _user(), _user()
    live = _origin(store, owner["user_id"])
    already = _origin(store, owner["user_id"], status="archived")
    keep = _origin(store, other["user_id"])
    assert users.delete(owner["user_id"]) == 1          # only the live one changed
    assert users.get_by_id(owner["user_id"]) is None
    for oid in (live, already):
        o = store.get_origin_by_id(oid)
        assert o["status"] == "archived" and o["admin_user_id"] is None
    assert "archived_at" in store.get_origin_by_id(live)
    assert store.get_origin_by_id(keep)["status"] == "active"


# ---------------------------------------------------------------- origins

def test_origin_shape_parity(store):
    owner = _user()
    oid = _origin(store, owner["user_id"], connection_mode="direct", origin_scheme="https",
                  tech_stack_tags=["nginx"])
    o = store.get_origin_by_id(oid)
    assert o["id"] == oid and o["admin_user_id"] == owner["user_id"]
    assert o["port"] == 8080 and isinstance(o["port"], int)
    assert o["connection_mode"] == "direct" and o["origin_scheme"] == "https"
    assert o["tech_stack_tags"] == ["nginx"]
    _parse(o["created_at"])
    assert [x["id"] for x in store.get_origins_by_user(owner["user_id"])] == [oid]
    assert oid in [x["id"] for x in store.list_origins()]


def test_malformed_ids_are_not_found_not_errors():
    from services.pg_store import PgStore
    store = PgStore()
    assert store.get_origin_by_id("not-a-uuid") == {}
    assert store.get_domain("d1") is None
    assert store.get_origins_by_user("u1") == []
    assert store.update_origin("o1", {"label": "x"}) is False
    assert store.create_origin({"id": str(uuid.uuid4()), "admin_user_id": "u1", "label": "x",
                                "ip": "1.2.3.4", "port": 80}) is False
    assert store.create_origin({"id": str(uuid.uuid4()), "admin_user_id": str(uuid.uuid4()),
                                "label": "x", "ip": "1.2.3.4", "port": 80}) is False  # no such user


def test_update_origin_rejects_unknown_fields():
    from services.pg_store import PgStore
    store = PgStore()
    oid = _origin(store, _user()["user_id"])
    with pytest.raises(ValueError):
        store.update_origin(oid, {"bogus": 1})
    assert store.update_origin(oid, {"label": "renamed", "updated_at": "2026-10-15T00:00:00Z"}) is True
    assert store.get_origin_by_id(oid)["label"] == "renamed"


def test_viewer_and_editor_grants_are_independent(store):
    oid = _origin(store, _user()["user_id"])
    member = _user()["user_id"]
    assert store.add_origin_viewer(oid, member) and store.add_origin_editor(oid, member)
    o = store.get_origin_by_id(oid)
    assert o["viewer_user_ids"] == {member} and o["editor_user_ids"] == {member}
    store.remove_origin_editor(oid, member)
    o = store.get_origin_by_id(oid)
    assert o["viewer_user_ids"] == {member} and not o.get("editor_user_ids")
    assert [x["id"] for x in store.get_origins_shared_with(member)] == [oid]


def test_tunnel_hosts_and_credential_never_ride_along():
    from services.pg_store import PgStore
    from services.dynamodb_service import DomainAlreadyClaimed
    store = PgStore()
    a = _origin(store, _user()["user_id"])
    b = _origin(store, _user()["user_id"])
    assert store.update_origin(a, {"tunnel_token_hash": "a" * 64, "tunnel_domains": ["App.Example.com", "b.example.com"],
                                   "tunnel_token_issued_at": 1760000000}) is True
    o = store.get_origin_by_id(a)
    assert o["tunnel_domains"] == ["app.example.com", "b.example.com"]
    assert "tunnel_token_hash" not in o
    assert store.get_agent_credential(a) == {"token_hash": "a" * 64, "issued_at": 1760000000}
    with pytest.raises(DomainAlreadyClaimed):
        store.update_origin(b, {"tunnel_token_hash": "b" * 64, "tunnel_domains": ["app.example.com"]})
    # the failed issue wrote nothing for b (one transaction)
    assert store.get_agent_credential(b) is None and not store.get_origin_by_id(b).get("tunnel_domains")


def test_archive_and_restore(store):
    oid = _origin(store, _user()["user_id"])
    assert store.delete_origin(oid)
    assert store.get_origin_by_id(oid)["status"] == "archived"
    assert store.restore_origin(oid)
    o = store.get_origin_by_id(oid)
    assert o["status"] == "active" and "archived_at" not in o


# ---------------------------------------------------------------- domains

def _domain(store, oid, name, verified):
    return store.create_domain({"id": str(uuid.uuid4()), "origin_id": oid, "domain_name": name,
                                "verification_token": "waf-token-x", "dns_verified": verified,
                                "ssl_status": "pending" if verified else "none",
                                "created_at": datetime.utcnow().isoformat() + "Z"})


def test_domain_crud_parity(store):
    from services.dynamodb_service import DuplicateDomain
    oid = _origin(store, _user()["user_id"])
    d = _domain(store, oid, "shop.example.com", False)
    got = store.get_domain(d["id"])
    assert {k: got[k] for k in ("origin_id", "domain_name", "dns_verified", "ssl_status")} == {
        "origin_id": oid, "domain_name": "shop.example.com", "dns_verified": False, "ssl_status": "none"}
    _parse(got["created_at"])
    with pytest.raises(DuplicateDomain):
        _domain(store, oid, "shop.example.com", True)
    store.update_domain(d["id"], {"dns_verified": True, "ssl_status": "pending"})
    assert store.get_domain(d["id"])["dns_verified"] is True
    assert [x["id"] for x in store.list_domains(origin_id=oid, dns_verified=True)] == [d["id"]]
    assert store.list_domains(dns_verified=False) == []
    assert store.get_origin_id_for_domain("SHOP.example.com:443") == oid
    assert store.delete_domains_for_origin(oid) == 1
    assert store.get_domain_by_name("shop.example.com") is None


def test_hostname_views_keep_their_filters():
    from services.pg_store import PgStore
    store = PgStore()
    owner = _user()["user_id"]
    live = _origin(store, owner, tunnel_domains=["tun.example.com"])
    gone = _origin(store, owner, status="archived")
    _domain(store, live, "verified.example.com", True)
    _domain(store, live, "unverified.example.com", False)
    _domain(store, gone, "archived.example.com", True)
    active = {h for h, _o in store.verified_hostnames_active()}
    assert active == {"verified.example.com", "tun.example.com"}
    owners = store.hostname_owner_map()
    # threat-intel attribution keeps unverified and archived hosts
    assert set(owners) == {"verified.example.com", "unverified.example.com", "archived.example.com",
                           "tun.example.com"}
    assert set(owners.values()) == {owner}


# -------------------------------------------------------------------- ssl

def test_ssl_upsert_keeps_unspecified_fields(store):
    store.upsert_ssl_cert("shop.example.com", {"domain": "shop.example.com", "status": "ok",
                                               "checked_at": "2026-10-15T00:00:00+00:00",
                                               "not_after": "2026-12-25T00:00:00+00:00",
                                               "issuer": "LE", "days_remaining": 70})
    store.upsert_ssl_cert("shop.example.com", {"domain": "shop.example.com", "status": "ok",
                                               "checked_at": "2026-10-16T00:00:00+00:00",
                                               "not_after": "2026-12-25T00:00:00+00:00",
                                               "days_remaining": 69})
    store.set_ssl_last_alerted("shop.example.com", "2026-10-16T01:00:00+00:00")
    cert = store.get_ssl_cert("shop.example.com")
    assert cert["issuer"] == "LE" and cert["days_remaining"] == 69
    assert datetime.fromisoformat(cert["last_alerted_at"]) == datetime.fromisoformat("2026-10-16T01:00:00+00:00")
    assert datetime.fromisoformat(cert["checked_at"]) == datetime.fromisoformat("2026-10-16T00:00:00+00:00")
