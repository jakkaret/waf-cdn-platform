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
