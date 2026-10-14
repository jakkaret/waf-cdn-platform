"""Seed rows with real uuids through the store, for tests that used literal
ids ('o1', 'u1', 'd1', 'o-direct') which PostgreSQL's uuid columns reject.
Works in both modes: the in-memory fake and DATA_BACKEND=postgres."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def make_user(email: Optional[str] = None, username: Optional[str] = None,
              role: str = "viewer", password: str = "Sup3rSecret!") -> dict:
    from services.rbac import auth_service
    tag = uuid.uuid4().hex[:8]
    return auth_service.create_user(
        email=email or f"user-{tag}@example.com",
        username=username or f"user_{tag}",
        password=password,
        role=role,
    )


def make_origin(owner: dict, db=None, **fields) -> dict:
    from services.dynamodb_service import DynamoDBService
    db = db or DynamoDBService()
    now = _now()
    origin = {
        "id": str(uuid.uuid4()),
        "admin_user_id": owner["user_id"],
        "label": fields.pop("label", "seed-origin"),
        "ip": fields.pop("ip", "203.0.113.10"),
        "port": fields.pop("port", 80),
        "status": fields.pop("status", "active"),
        "created_at": now,
        "updated_at": now,
        **fields,
    }
    db.create_origin(origin)
    return db.get_origin_by_id(origin["id"]) or origin


def make_domain(origin: dict, domain_name: Optional[str] = None, db=None,
                dns_verified: bool = True, **fields) -> dict:
    from services.dynamodb_service import DynamoDBService
    db = db or DynamoDBService()
    now = _now()
    domain = {
        "id": str(uuid.uuid4()),
        "origin_id": origin["id"],
        "domain_name": domain_name or f"site-{uuid.uuid4().hex[:8]}.example.com",
        "verification_token": f"waf-token-{uuid.uuid4().hex[:16]}",
        "dns_verified": dns_verified,
        "ssl_status": "pending" if dns_verified else "none",
        "created_at": now,
        "updated_at": now,
        **fields,
    }
    db.create_domain(domain)
    return db.get_domain(domain["id"]) or domain


# ---------------------------------------------------------------------------
# Fixed-id seeding for tests that build rows by hand. uid("o-direct") is a
# stable uuid derived from the old literal, so a test keeps its readable
# names while PostgreSQL gets real uuids. seed_origin/seed_domain create the
# owner user / parent origin when missing so foreign keys hold in pg mode.
# ---------------------------------------------------------------------------
_NS = uuid.UUID("6f0d3c1e-6b1f-4e0a-9d0e-7a3c2b1d4e5f")


def uid(label: str) -> str:
    return str(uuid.uuid5(_NS, label))


def _pg_mode() -> bool:
    from services.dynamodb_service import data_backend
    return data_backend() == "postgres"


def ensure_user(user_id: str, role: str = "viewer") -> str:
    """Make sure a user row with exactly this id exists; return the id."""
    if not user_id:
        return user_id
    if _pg_mode():
        from db import pool
        pool.exec_("INSERT INTO users (user_id, email, username, role, password_hash) "
                   "VALUES (%s, %s, %s, %s, '$argon2id$seed') ON CONFLICT (user_id) DO NOTHING",
                   (user_id, f"{user_id}@seed.example.com", f"seed_{user_id[:8]}", role))
    else:
        from services.rbac import auth_service
        if not auth_service.get_user_by_id(user_id):
            auth_service.users_table.put_item(Item={
                "user_id": user_id, "email": f"{user_id}@seed.example.com",
                "username": f"seed_{user_id[:8]}", "role": role, "password_hash": ""})
    return user_id


def as_id(value):
    """A uuid stays as is; a legacy literal id ('o-good') becomes uid(it)."""
    if value is None:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return uid(str(value))


def seed_origin(db, item: dict) -> dict:
    """Insert an origin dict as given. Legacy literal ids are mapped with
    as_id(), so compare against uid('o-good') when asserting on ids."""
    row = dict(item)
    for key in ("id", "admin_user_id"):
        if row.get(key):
            row[key] = as_id(row[key])
    row.setdefault("admin_user_id", uid("seed-owner"))
    row.setdefault("label", "seed-origin")
    row.setdefault("ip", "203.0.113.10")
    row.setdefault("port", 80)
    row.setdefault("created_at", _now())
    row.setdefault("updated_at", row["created_at"])
    if row.get("admin_user_id"):
        ensure_user(row["admin_user_id"])
    assert db.create_origin(row) is not False, row
    return row


def seed_domain(db, item: dict) -> dict:
    """Insert a domain dict as given (ids through as_id()); creates its
    origin when missing."""
    row = dict(item)
    for key in ("id", "origin_id"):
        if row.get(key):
            row[key] = as_id(row[key])
    row.setdefault("id", str(uuid.uuid4()))
    row.setdefault("origin_id", uid("seed-origin"))
    row.setdefault("verification_token", f"waf-token-{uuid.uuid4().hex[:16]}")
    row.setdefault("dns_verified", False)
    row.setdefault("ssl_status", "none")
    row.setdefault("created_at", _now())
    row.setdefault("updated_at", row["created_at"])
    if not db.get_origin_by_id(row["origin_id"]):
        seed_origin(db, {"id": row["origin_id"]})
    db.create_domain(row)
    return row
