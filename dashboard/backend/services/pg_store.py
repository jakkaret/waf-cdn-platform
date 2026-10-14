"""PostgreSQL implementation of the control-plane store (schema `waf`).

Selected with DATA_BACKEND=postgres: services/dynamodb_service.py then
exports PgStore under the old DynamoDBService name, so the 26+ modules that
import it need no change.

Method groups move here phase by phase (migration plan Phases 3-5). Until a
group is implemented it is inherited from the DynamoDB-backed store, which in
production fails exactly as it did before the switch. That base class is
removed in Phase 7, once every method is SQL.

Returned dicts keep the DynamoDB-era shape: ids as str, the timestamp format
each table had (db/values.py), and optional attributes absent rather than None.

__init__ does no I/O: modules build this at import time.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from psycopg import sql

from db import pool
from db.errors import ForeignKeyConflict, UniqueConflict
from db.values import as_uuid, from_epoch, epoch_int, iso_offset, iso_z_us, parse_ts
from services.dynamodb_service import DomainAlreadyClaimed, DuplicateDomain, _DynamoBackedStore

logger = logging.getLogger(__name__)


# origins columns callers may set through create_origin/update_origin.
_ORIGIN_COLUMNS = {
    "admin_user_id", "label", "ip", "port", "status", "connection_mode", "origin_scheme",
    "is_tunnel", "tunnel_name", "tech_stack_tags", "managed_ruleset_mode",
    "managed_ruleset_version", "created_at", "updated_at", "archived_at", "deleted_at",
}
_ORIGIN_TS = {"created_at", "updated_at", "archived_at", "deleted_at"}
# Stored in child tables, written in the same transaction as the origin row.
_ORIGIN_TUNNEL_KEYS = {"tunnel_domains", "tunnel_token_hash", "tunnel_token_issued_at"}

_ORIGIN_SELECT = """
SELECT o.*,
       COALESCE((SELECT array_agg(m.user_id::text ORDER BY m.granted_at)
                   FROM origin_members m WHERE m.origin_id = o.id AND m.role = 'viewer'), '{}') AS viewer_user_ids,
       COALESCE((SELECT array_agg(m.user_id::text ORDER BY m.granted_at)
                   FROM origin_members m WHERE m.origin_id = o.id AND m.role = 'editor'), '{}') AS editor_user_ids,
       COALESCE((SELECT array_agg(t.domain_name ORDER BY t.position, t.domain_name)
                   FROM origin_tunnel_domains t WHERE t.origin_id = o.id), '{}') AS tunnel_domains
FROM origins o
"""

_DOMAIN_COLUMNS = {"dns_verified", "ssl_status", "verification_token", "updated_at"}
_SSL_COLUMNS = {"status", "checked_at", "not_after", "issuer", "days_remaining", "error", "last_alerted_at"}
_SSL_TS = {"checked_at", "not_after", "last_alerted_at"}


def _norm_host(name: Any) -> str:
    return str(name or "").strip().lower().rstrip(".")


class PgStore(_DynamoBackedStore):
    backend = "postgres"

    def __init__(self):
        # The inherited (not yet converted) methods need the boto3 table
        # handles; building them is local object construction, not I/O.
        super().__init__()

    def ping(self) -> bool:
        """Reachability probe for /api/system/status (raises on failure)."""
        if not pool.ping(timeout=1.0):
            raise ConnectionError("PostgreSQL unreachable")
        return True

    # ------------------------------------------------------------------
    # origins
    # ------------------------------------------------------------------
    @staticmethod
    def _to_origin(row: Optional[dict]) -> Dict[str, Any]:
        if not row:
            return {}
        origin: Dict[str, Any] = {
            "id": str(row["id"]),
            "admin_user_id": str(row["admin_user_id"]) if row["admin_user_id"] else None,
            "label": row["label"],
            "ip": row["ip"],
            "port": int(row["port"]),
            "status": row["status"],
            "managed_ruleset_mode": row["managed_ruleset_mode"],
            "created_at": iso_z_us(row["created_at"]),
            "updated_at": iso_z_us(row["updated_at"]),
        }
        for key in ("connection_mode", "origin_scheme", "tunnel_name"):
            if row.get(key) is not None:
                origin[key] = row[key]
        if row.get("is_tunnel"):
            origin["is_tunnel"] = True
        if row.get("managed_ruleset_version") is not None:
            origin["managed_ruleset_version"] = int(row["managed_ruleset_version"])
        if row.get("tech_stack_tags"):
            origin["tech_stack_tags"] = list(row["tech_stack_tags"])
        for key in ("archived_at", "deleted_at"):
            if row.get(key) is not None:
                origin[key] = iso_z_us(row[key])
        if row.get("viewer_user_ids"):
            origin["viewer_user_ids"] = set(row["viewer_user_ids"])
        if row.get("editor_user_ids"):
            origin["editor_user_ids"] = set(row["editor_user_ids"])
        if row.get("tunnel_domains"):
            origin["tunnel_domains"] = list(row["tunnel_domains"])
        # tunnel_token_hash is deliberately never returned: it lives in
        # origin_agent_credentials and only get_agent_credential() reads it.
        return origin

    @staticmethod
    def _origin_value(key: str, value: Any) -> Any:
        if key in _ORIGIN_TS:
            return parse_ts(value)
        if key in ("admin_user_id",):
            return as_uuid(value)
        if key == "tech_stack_tags":
            return list(value or [])
        if key == "port":
            return int(value)
        if key == "is_tunnel":
            return bool(value)
        if key == "managed_ruleset_version" and value is not None:
            return int(value)
        return value

    def _write_tunnel_fields(self, origin_id: str, data: Dict[str, Any]) -> None:
        """tunnel_domains -> origin_tunnel_domains (replaced wholesale);
        tunnel_token_hash/_issued_at -> origin_agent_credentials."""
        if "tunnel_domains" in data:
            hosts: List[str] = []
            for host in data.get("tunnel_domains") or []:
                h = _norm_host(host)
                if h and h not in hosts:
                    hosts.append(h)
            pool.exec_("DELETE FROM origin_tunnel_domains WHERE origin_id = %s", (origin_id,))
            for position, host in enumerate(hosts):
                try:
                    pool.exec_("INSERT INTO origin_tunnel_domains (origin_id, domain_name, position) "
                               "VALUES (%s, %s, %s)", (origin_id, host, position))
                except UniqueConflict as exc:
                    raise DomainAlreadyClaimed(
                        f"Domain '{host}' is already claimed by another origin's tunnel") from exc
        if data.get("tunnel_token_hash"):
            issued = from_epoch(data.get("tunnel_token_issued_at")) if data.get("tunnel_token_issued_at") else None
            pool.exec_(
                "INSERT INTO origin_agent_credentials (origin_id, token_hash, issued_at, issued_by) "
                "VALUES (%s, %s, COALESCE(%s, now()), %s) "
                "ON CONFLICT (origin_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, "
                "issued_at = EXCLUDED.issued_at, issued_by = EXCLUDED.issued_by",
                (origin_id, data["tunnel_token_hash"], issued, as_uuid(data.get("tunnel_token_issued_by"))),
            )

    def create_origin(self, origin_data: Dict) -> bool:
        """Insert an origin (and its tunnel hosts). False when the owner is
        not a known user (e.g. a tunnel whose JWT names a deleted account),
        so callers skip it instead of answering 500."""
        oid = as_uuid(origin_data.get("id"))
        owner = as_uuid(origin_data.get("admin_user_id"))
        if oid is None or owner is None:
            return False
        cols = {k: self._origin_value(k, v) for k, v in origin_data.items() if k in _ORIGIN_COLUMNS}
        cols["id"] = oid
        cols.setdefault("status", "pending")
        names = list(cols)
        query = sql.SQL("INSERT INTO origins ({}) VALUES ({})").format(
            sql.SQL(", ").join(sql.Identifier(n) for n in names),
            sql.SQL(", ").join(sql.Placeholder() * len(names)),
        )
        try:
            with pool.transaction():
                pool.exec_(query.as_string(), [cols[n] for n in names])
                self._write_tunnel_fields(oid, origin_data)
        except ForeignKeyConflict:
            return False
        return True

    def get_origin_by_id(self, origin_id: str) -> Dict:
        oid = as_uuid(origin_id)
        if oid is None:
            return {}
        try:
            return self._to_origin(pool.q1(_ORIGIN_SELECT + " WHERE o.id = %s", (oid,)))
        except Exception as e:
            logger.error("get_origin_by_id failed: %s", e)
            return {}

    def get_origins_by_user(self, admin_user_id: str) -> List[Dict]:
        owner = as_uuid(admin_user_id)
        if owner is None:
            return []
        rows = pool.q(_ORIGIN_SELECT + " WHERE o.admin_user_id = %s ORDER BY o.created_at", (owner,))
        return [self._to_origin(r) for r in rows]

    def get_origins_shared_with(self, user_id: str) -> List[Dict]:
        """Origins where the user holds a viewer or editor grant."""
        uid = as_uuid(user_id)
        if uid is None:
            return []
        rows = pool.q(_ORIGIN_SELECT + " WHERE o.id IN (SELECT origin_id FROM origin_members "
                      "WHERE user_id = %s) ORDER BY o.created_at", (uid,))
        return [self._to_origin(r) for r in rows]

    def list_origins(self) -> List[Dict]:
        return [self._to_origin(r) for r in pool.q(_ORIGIN_SELECT + " ORDER BY o.created_at")]

    def update_origin(self, origin_id: str, update_data: Dict) -> bool:
        oid = as_uuid(origin_id)
        if oid is None:
            return False
        unknown = set(update_data) - _ORIGIN_COLUMNS - _ORIGIN_TUNNEL_KEYS - {"id"}
        if unknown:
            raise ValueError(f"unknown origin field(s): {', '.join(sorted(unknown))}")
        cols = {k: self._origin_value(k, v) for k, v in update_data.items() if k in _ORIGIN_COLUMNS}
        with pool.transaction():
            if cols:
                query = sql.SQL("UPDATE origins SET {} WHERE id = %s").format(
                    sql.SQL(", ").join(
                        sql.SQL("{} = {}").format(sql.Identifier(k), sql.Placeholder()) for k in cols))
                if pool.exec_(query.as_string(), [*cols.values(), oid]) == 0:
                    return False
            elif not pool.q1("SELECT 1 AS x FROM origins WHERE id = %s", (oid,)):
                return False
            self._write_tunnel_fields(oid, update_data)
        return True

    def get_agent_credential(self, origin_id: str) -> Optional[Dict]:
        """{token_hash, issued_at (epoch int)} for the verify-agent path only."""
        oid = as_uuid(origin_id)
        if oid is None:
            return None
        row = pool.q1("SELECT token_hash, issued_at FROM origin_agent_credentials WHERE origin_id = %s", (oid,))
        if not row:
            return None
        return {"token_hash": row["token_hash"], "issued_at": epoch_int(row["issued_at"])}

    def _set_member(self, origin_id: str, user_id: str, role: str, add: bool,
                    granted_by: Optional[str] = None) -> bool:
        oid, uid = as_uuid(origin_id), as_uuid(user_id)
        if oid is None or uid is None:
            return False
        try:
            if add:
                pool.exec_("INSERT INTO origin_members (origin_id, user_id, role, granted_by) "
                           "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                           (oid, uid, role, as_uuid(granted_by)))
            else:
                pool.exec_("DELETE FROM origin_members WHERE origin_id = %s AND user_id = %s AND role = %s",
                           (oid, uid, role))
            return True
        except Exception as e:
            logger.error("origin member %s %s failed: %s", "add" if add else "remove", role, e)
            return False

    def add_origin_viewer(self, origin_id: str, viewer_user_id: str, granted_by: Optional[str] = None) -> bool:
        return self._set_member(origin_id, viewer_user_id, "viewer", True, granted_by)

    def remove_origin_viewer(self, origin_id: str, viewer_user_id: str) -> bool:
        return self._set_member(origin_id, viewer_user_id, "viewer", False)

    def add_origin_editor(self, origin_id: str, editor_user_id: str, granted_by: Optional[str] = None) -> bool:
        return self._set_member(origin_id, editor_user_id, "editor", True, granted_by)

    def remove_origin_editor(self, origin_id: str, editor_user_id: str) -> bool:
        return self._set_member(origin_id, editor_user_id, "editor", False)

    def delete_origin(self, origin_id: str) -> bool:
        """Archive (soft delete)."""
        oid = as_uuid(origin_id)
        if oid is None:
            return False
        return pool.exec_("UPDATE origins SET status = 'archived', archived_at = now(), deleted_at = NULL, "
                          "updated_at = now() WHERE id = %s", (oid,)) > 0

    def restore_origin(self, origin_id: str) -> bool:
        oid = as_uuid(origin_id)
        if oid is None:
            return False
        return pool.exec_("UPDATE origins SET status = 'active', archived_at = NULL, deleted_at = NULL, "
                          "updated_at = now() WHERE id = %s", (oid,)) > 0

    def hard_delete_origin(self, origin_id: str) -> None:
        oid = as_uuid(origin_id)
        if oid is not None:
            pool.exec_("DELETE FROM origins WHERE id = %s", (oid,))

    # ------------------------------------------------------------------
    # domains
    # ------------------------------------------------------------------
    @staticmethod
    def _to_domain(row: Optional[dict]) -> Optional[Dict]:
        if not row:
            return None
        return {
            "id": str(row["id"]),
            "origin_id": str(row["origin_id"]),
            "domain_name": row["domain_name"],
            "verification_token": row["verification_token"],
            "dns_verified": bool(row["dns_verified"]),
            "ssl_status": row["ssl_status"],
            "created_at": iso_z_us(row["created_at"]),
            "updated_at": iso_z_us(row["updated_at"]),
        }

    def get_domain(self, domain_id: str) -> Optional[Dict]:
        did = as_uuid(domain_id)
        if did is None:
            return None
        return self._to_domain(pool.q1("SELECT * FROM domains WHERE id = %s", (did,)))

    def get_domain_by_name(self, domain_name: str) -> Optional[Dict]:
        name = _norm_host(domain_name)
        if not name:
            return None
        return self._to_domain(pool.q1("SELECT * FROM domains WHERE domain_name = %s", (name,)))

    def list_domains(self, origin_id: Optional[str] = None,
                     dns_verified: Optional[bool] = None) -> List[Dict]:
        clauses, params = [], []
        if origin_id is not None:
            oid = as_uuid(origin_id)
            if oid is None:
                return []
            clauses.append("origin_id = %s")
            params.append(oid)
        if dns_verified is not None:
            clauses.append("dns_verified = %s" if dns_verified else "NOT dns_verified")
            if dns_verified:
                params.append(True)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return [self._to_domain(r) for r in pool.q(f"SELECT * FROM domains{where} ORDER BY created_at", params)]

    def get_domains_by_origin_ids(self, origin_ids: List[str]) -> List[Dict]:
        ids = [u for u in (as_uuid(o) for o in origin_ids) if u]
        if not ids:
            return []
        rows = pool.q("SELECT * FROM domains WHERE origin_id = ANY(%s::uuid[]) ORDER BY created_at", (ids,))
        return [self._to_domain(r) for r in rows]

    def get_origin_id_for_domain(self, domain_name: str) -> str:
        """Exact Host -> owning origin via BYO domains only ("" when none)."""
        clean = _norm_host(domain_name)
        if ":" in clean and not clean.startswith("["):
            clean = clean.split(":", 1)[0]
        if not clean:
            return ""
        try:
            row = pool.q1("SELECT origin_id FROM domains WHERE domain_name = %s", (clean,))
            return str(row["origin_id"]) if row else ""
        except Exception as e:
            logger.error("Failed to resolve origin for domain %s: %s", clean, e)
            return ""

    def create_domain(self, item: Dict) -> Dict:
        name = _norm_host(item.get("domain_name"))
        oid = as_uuid(item.get("origin_id"))
        if not name or oid is None:
            raise ValueError("domain needs a hostname and an existing origin")
        did = as_uuid(item.get("id"))
        try:
            row = pool.q1(
                "INSERT INTO domains (id, origin_id, domain_name, verification_token, dns_verified, "
                "ssl_status, created_at, updated_at) VALUES (COALESCE(%s::uuid, gen_random_uuid()), "
                "%s, %s, %s, %s, %s, COALESCE(%s, now()), COALESCE(%s, now())) RETURNING *",
                (did, oid, name, item.get("verification_token") or "", bool(item.get("dns_verified", False)),
                 item.get("ssl_status") or "none", parse_ts(item.get("created_at")),
                 parse_ts(item.get("updated_at"))),
            )
        except UniqueConflict as exc:
            raise DuplicateDomain(f"Domain name {name} is already registered.") from exc
        except ForeignKeyConflict as exc:
            raise ValueError("origin not found") from exc
        return self._to_domain(row)

    def update_domain(self, domain_id: str, fields: Dict[str, Any]) -> None:
        did = as_uuid(domain_id)
        if did is None:
            return
        unknown = set(fields) - _DOMAIN_COLUMNS
        if unknown:
            raise ValueError(f"unknown domain field(s): {', '.join(sorted(unknown))}")
        values = {k: (parse_ts(v) if k == "updated_at" else v) for k, v in fields.items()}
        values.setdefault("updated_at", None)
        assignments = [sql.SQL("{} = {}").format(sql.Identifier(k), sql.Placeholder())
                       for k in values if k != "updated_at"]
        assignments.append(sql.SQL("updated_at = COALESCE({}, now())").format(sql.Placeholder()))
        params = [v for k, v in values.items() if k != "updated_at"] + [values["updated_at"], did]
        query = sql.SQL("UPDATE domains SET {} WHERE id = %s").format(sql.SQL(", ").join(assignments))
        pool.exec_(query.as_string(), params)

    def delete_domain(self, domain_id: str) -> None:
        did = as_uuid(domain_id)
        if did is not None:
            pool.exec_("DELETE FROM domains WHERE id = %s", (did,))

    def delete_domains_for_origin(self, origin_id: str) -> int:
        oid = as_uuid(origin_id)
        if oid is None:
            return 0
        return pool.exec_("DELETE FROM domains WHERE origin_id = %s", (oid,))

    # ------------------------------------------------------------------
    # hostnames (view origin_hostnames)
    # ------------------------------------------------------------------
    def verified_hostnames_active(self) -> List[tuple]:
        """[(hostname, origin_id)]: DNS-verified BYO domains and tunnel hosts
        of origins that are not archived/deleted. Unverified BYO domains are
        excluded (otherwise anyone could add someone else's hostname to get
        their rules applied to it, or a certificate issued for it)."""
        rows = pool.q("SELECT hostname, origin_id FROM origin_hostnames "
                      "WHERE dns_verified AND origin_status NOT IN ('archived', 'deleted') "
                      "ORDER BY source, hostname")
        return [(r["hostname"], str(r["origin_id"])) for r in rows]

    def hostname_owner_map(self) -> Dict[str, str]:
        """host -> owning admin_user_id for every BYO and tunnel hostname,
        verified or not, whatever the origin status (threat-intel
        attribution). A BYO row wins over a tunnel row for the same host."""
        rows = pool.q("SELECT h.hostname, h.source, o.admin_user_id FROM origin_hostnames h "
                      "JOIN origins o ON o.id = h.origin_id WHERE o.admin_user_id IS NOT NULL "
                      "ORDER BY (h.source = 'byo'), h.hostname")
        return {_norm_host(r["hostname"]): str(r["admin_user_id"]) for r in rows}

    # ------------------------------------------------------------------
    # ssl certificates
    # ------------------------------------------------------------------
    @staticmethod
    def _to_cert(row: Optional[dict]) -> Optional[Dict]:
        if not row:
            return None
        cert: Dict[str, Any] = {"id": row["hostname"], "domain": row["hostname"], "status": row["status"],
                                "checked_at": iso_offset(row["checked_at"]),
                                "days_remaining": row["days_remaining"]}
        for key in ("not_after", "last_alerted_at"):
            if row.get(key) is not None:
                cert[key] = iso_offset(row[key])
        for key in ("issuer", "error"):
            if row.get(key) is not None:
                cert[key] = row[key]
        return cert

    def get_ssl_cert(self, hostname: str) -> Optional[Dict]:
        host = _norm_host(hostname)
        if not host:
            return None
        return self._to_cert(pool.q1("SELECT * FROM ssl_certificates WHERE hostname = %s", (host,)))

    def upsert_ssl_cert(self, hostname: str, record: Dict) -> None:
        """Insert or update the probe result; only the given fields change
        (an absent field keeps its stored value, as UpdateItem SET did)."""
        host = _norm_host(hostname)
        fields = {k: (parse_ts(v) if k in _SSL_TS else v) for k, v in record.items() if k in _SSL_COLUMNS}
        if not host or not fields:
            return
        names = list(fields)
        if "status" in fields and "checked_at" in fields:
            query = sql.SQL(
                "INSERT INTO ssl_certificates (hostname, {cols}) VALUES (%s, {vals}) "
                "ON CONFLICT (hostname) DO UPDATE SET {sets}").format(
                cols=sql.SQL(", ").join(sql.Identifier(n) for n in names),
                vals=sql.SQL(", ").join(sql.Placeholder() * len(names)),
                sets=sql.SQL(", ").join(
                    sql.SQL("{} = EXCLUDED.{}").format(sql.Identifier(n), sql.Identifier(n)) for n in names),
            )
            pool.exec_(query.as_string(), [host, *fields.values()])
        else:
            query = sql.SQL("UPDATE ssl_certificates SET {} WHERE hostname = %s").format(
                sql.SQL(", ").join(sql.SQL("{} = {}").format(sql.Identifier(n), sql.Placeholder()) for n in names))
            pool.exec_(query.as_string(), [*fields.values(), host])

    def set_ssl_last_alerted(self, hostname: str, ts: str) -> None:
        self.upsert_ssl_cert(hostname, {"last_alerted_at": ts})


# ----------------------------------------------------------------------
# users (waf.users + waf.user_identities), used by services/auth_service.py
# ----------------------------------------------------------------------
_USER_SELECT = (
    "SELECT u.user_id, u.email, u.username, u.role, u.password_hash, u.auth_provider, "
    "u.avatar_url, u.telegram_chat_id, u.share_threat_intel, u.created_at, u.last_login, "
    "i.provider_user_id AS provider_id "
    "FROM users u LEFT JOIN user_identities i "
    "ON i.user_id = u.user_id AND i.provider = u.auth_provider "
)


class PgUserRepository:
    """Accounts in PostgreSQL. Returned dicts keep the DynamoDB-era shape:
    user_id as str, password_hash '' for OAuth accounts, created_at /
    last_login as isoformat()+'Z', provider_id from the linked identity, and
    avatar_url / telegram_chat_id / provider_id absent rather than None."""

    @staticmethod
    def _to_user(row: Optional[dict]) -> Optional[Dict]:
        if not row:
            return None
        user = {
            "user_id": str(row["user_id"]),
            "email": row["email"],
            "username": row["username"],
            "role": row["role"],
            "password_hash": row["password_hash"] or "",
            "auth_provider": row["auth_provider"],
            "share_threat_intel": bool(row["share_threat_intel"]),
            "created_at": iso_z_us(row["created_at"]),
            "last_login": iso_z_us(row["last_login"]),
        }
        for key in ("avatar_url", "telegram_chat_id", "provider_id"):
            if row.get(key):
                user[key] = row[key]
        return user

    def get_by_id(self, user_id: str) -> Optional[Dict]:
        uid = as_uuid(user_id)
        if uid is None:
            return None
        return self._to_user(pool.q1(_USER_SELECT + "WHERE u.user_id = %s", (uid,)))

    def get_by_email(self, email: str) -> Optional[Dict]:
        if not email:
            return None
        return self._to_user(pool.q1(
            _USER_SELECT + "WHERE lower(u.email) = lower(%s) AND u.email <> ''", (email,)))

    def get_by_provider(self, provider: str, provider_id: str) -> Optional[Dict]:
        if not provider_id:
            return None
        return self._to_user(pool.q1(
            _USER_SELECT.replace("LEFT JOIN", "JOIN") + "WHERE i.provider = %s AND i.provider_user_id = %s",
            (provider, str(provider_id))))

    def create(self, email: str, username: str, password_hash: Optional[str], role: str,
               auth_provider: str, provider_id: Optional[str], avatar_url: Optional[str]) -> Dict:
        """Insert the user and its OAuth/Telegram identity in one transaction.
        A duplicate email or identity raises UniqueConflict (a ValueError)."""
        role = role if role in ("admin", "viewer") else "viewer"
        with pool.transaction():
            row = pool.q1(
                "INSERT INTO users (email, username, role, password_hash, auth_provider, avatar_url, "
                "last_login) VALUES (%s, %s, %s, %s, %s, %s, now()) RETURNING user_id",
                (email, username, role, password_hash or None, auth_provider or "local", avatar_url or None),
            )
            if provider_id and auth_provider in ("google", "telegram"):
                pool.exec_("INSERT INTO user_identities (provider, provider_user_id, user_id) "
                           "VALUES (%s, %s, %s)", (auth_provider, str(provider_id), row["user_id"]))
        return self.get_by_id(row["user_id"])

    def touch_login(self, user_id: str) -> None:
        uid = as_uuid(user_id)
        if uid is not None:
            pool.exec_("UPDATE users SET last_login = now() WHERE user_id = %s", (uid,))

    def list(self) -> List[Dict]:
        return [self._to_user(r) for r in pool.q(_USER_SELECT + "ORDER BY u.created_at")]

    def count(self) -> int:
        return int(pool.q1("SELECT count(*) AS n FROM users")["n"])

    def list_telegram_recipients(self) -> List[Dict]:
        return [self._to_user(r) for r in pool.q(
            _USER_SELECT + "WHERE u.telegram_chat_id IS NOT NULL ORDER BY u.created_at")]

    def set_field(self, user_id: str, column: str, value: Any) -> bool:
        if column not in ("role", "telegram_chat_id", "share_threat_intel", "avatar_url"):
            raise ValueError(f"unknown user field: {column}")
        uid = as_uuid(user_id)
        if uid is None:
            return False
        query = sql.SQL("UPDATE users SET {} = %s WHERE user_id = %s").format(sql.Identifier(column))
        return pool.exec_(query.as_string(), (value, uid)) > 0

    def delete(self, user_id: str) -> int:
        """Delete the user. Origins they still own are archived first in the
        same transaction (owner's decision 2026-10-15); the foreign key then
        clears their admin_user_id. Returns how many origins were archived."""
        uid = as_uuid(user_id)
        if uid is None:
            return 0
        with pool.transaction():
            archived = pool.exec_(
                "UPDATE origins SET status = 'archived', archived_at = COALESCE(archived_at, now()), "
                "updated_at = now() WHERE admin_user_id = %s AND status <> 'archived'", (uid,))
            pool.exec_("DELETE FROM users WHERE user_id = %s", (uid,))
        return archived
