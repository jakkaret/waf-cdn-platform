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

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------
    _ALERT_OPTIONAL = ("ai_summary", "rule_id", "attack_type", "severity", "edge_node", "message", "request_id")

    def _to_alert(self, row: dict) -> Dict[str, Any]:
        alert: Dict[str, Any] = {
            # NULL = not attributable; callers rely on the literal partition
            # name (a None would fall into the legacy substring host match).
            "origin_id": str(row["origin_id"]) if row["origin_id"] else self.ALERTS_UNATTRIBUTED,
            # The constant every alert carried; some UI still shows it.
            "user_id": "default-user",
            "alert_id": row["alert_id"],
            "ip": row["ip"],
            "url": row["url"],
            "status": row["status"],
            "timestamp": iso_z_us(row["created_at"]),
            "read": bool(row["is_read"]),
        }
        if row.get("domain"):
            alert["domain"] = row["domain"]
        for key in self._ALERT_OPTIONAL:
            if row.get(key) is not None:
                alert[key] = row[key]
        return alert

    def _insert_alert(self, item: Dict[str, Any]) -> bool:
        origin = item.get("origin_id")
        oid = None if origin in (None, "", self.ALERTS_UNATTRIBUTED) else as_uuid(origin)
        created = parse_ts(item.get("timestamp")) if item.get("timestamp") else None
        rowcount = pool.exec_(
            "INSERT INTO alerts (alert_id, origin_id, request_id, domain, ip, url, status, rule_id, "
            "attack_type, severity, edge_node, ai_summary, message, created_at, is_read) "
            "VALUES (%s, (SELECT id FROM origins WHERE id = %s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
            "COALESCE(%s, now()), %s) ON CONFLICT (alert_id) DO NOTHING",
            (str(item["alert_id"]), oid, item.get("request_id"), str(item.get("domain") or "").strip().lower(),
             str(item.get("ip") or "unknown"), str(item.get("url") or ""), str(item.get("status") or ""),
             item.get("rule_id"), item.get("attack_type"), item.get("severity"), item.get("edge_node"),
             item.get("ai_summary"), item.get("message"), created, bool(item.get("read", False))),
        )
        return rowcount > 0

    def put_alert(self, item: Dict) -> None:
        self._insert_alert(item)

    def save_alert(self, user_id: str, alert_id: str, ip: str, url: str, status: str, message: str,
                   ai_summary: str = None, rule_id: str = None, attack_type: str = None,
                   severity: str = None, edge_node: str = None, domain: str = None,
                   origin_id: str = None) -> bool:
        try:
            resolved = str(origin_id or "").strip()
            if not resolved and domain:
                resolved = self.get_origin_id_for_domain(domain)
            self._insert_alert({
                "alert_id": alert_id, "origin_id": resolved or None, "ip": ip, "url": url,
                "status": str(status), "message": message, "ai_summary": ai_summary, "rule_id": rule_id,
                "attack_type": attack_type, "severity": severity, "edge_node": edge_node, "domain": domain,
            })
            return True
        except Exception as e:
            logger.error("Failed to save alert: %s", e)
            return False

    def get_all_alerts(self, max_items: int = 2000) -> List[Dict]:
        try:
            rows = pool.q("SELECT * FROM alerts ORDER BY created_at DESC LIMIT %s", (int(max_items),))
            return [self._to_alert(r) for r in rows]
        except Exception as e:
            logger.error("Failed to fetch all alerts: %s", e)
            return []

    def get_alerts_for_origins(self, origin_ids: List[str], max_items: int = 2000) -> List[Dict]:
        ids = [u for u in (as_uuid(o) for o in origin_ids) if u]
        if not ids:
            return []
        rows = pool.q("SELECT * FROM alerts WHERE origin_id = ANY(%s::uuid[]) "
                      "ORDER BY created_at DESC LIMIT %s", (ids, int(max_items)))
        return [self._to_alert(r) for r in rows]

    def mark_alert_read(self, origin_id: str, alert_id: str) -> None:
        pool.exec_("UPDATE alerts SET is_read = true WHERE alert_id = %s", (str(alert_id),))

    def mark_alerts_read(self, alerts: List[Dict]) -> int:
        ids = [str(a["alert_id"]) for a in alerts if a.get("alert_id")]
        if not ids:
            return 0
        return pool.exec_("UPDATE alerts SET is_read = true WHERE alert_id = ANY(%s) AND NOT is_read", (ids,))

    # ------------------------------------------------------------------
    # postmortems
    # ------------------------------------------------------------------
    @staticmethod
    def _to_postmortem(row: dict) -> Dict[str, Any]:
        return {
            "id": str(row["id"]),
            "origin_id": str(row["origin_id"]),
            "origin_label": row["origin_label"],
            "created_by": str(row["created_by"]) if row["created_by"] else None,
            "created_by_username": row["created_by_username"],
            "created_at": iso_offset(row["created_at"]),
            "start_time": row["start_text"],
            "end_time": row["end_text"],
            "stats": row["stats"],
            "hourly_buckets": row["hourly_buckets"],
            "audit_events": row["audit_events"],
            "ai_narrative": row["ai_narrative"],
            "ai_narrative_degraded": bool(row["ai_narrative_degraded"]),
        }

    _PM_SELECT = ("SELECT *, to_char(start_time AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS start_text, "
                  "to_char(end_time AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS end_text FROM postmortems ")

    def save_postmortem(self, item: Dict) -> None:
        from psycopg.types.json import Jsonb
        pool.exec_(
            "INSERT INTO postmortems (id, origin_id, origin_label, created_by, created_by_username, created_at, "
            "start_time, end_time, stats, hourly_buckets, audit_events, ai_narrative, ai_narrative_degraded) "
            "VALUES (%s, %s, %s, %s, %s, COALESCE(%s, now()), %s::timestamp AT TIME ZONE 'UTC', "
            "%s::timestamp AT TIME ZONE 'UTC', %s, %s, %s, %s, %s)",
            (as_uuid(item.get("id")), as_uuid(item.get("origin_id")), item.get("origin_label") or "",
             as_uuid(item.get("created_by")), item.get("created_by_username") or "",
             parse_ts(item.get("created_at")), item.get("start_time"), item.get("end_time"),
             Jsonb(item.get("stats") or {}), Jsonb(item.get("hourly_buckets") or []),
             Jsonb(item.get("audit_events") or []), item.get("ai_narrative"),
             bool(item.get("ai_narrative_degraded", False))),
        )

    def list_postmortems(self, origin_ids: List[str], limit: Optional[int] = None) -> List[Dict]:
        ids = [u for u in (as_uuid(o) for o in origin_ids) if u]
        if not ids:
            return []
        query = self._PM_SELECT + "WHERE origin_id = ANY(%s::uuid[]) ORDER BY created_at DESC"
        params: list = [ids]
        if limit:
            query += " LIMIT %s"
            params.append(int(limit))
        return [self._to_postmortem(r) for r in pool.q(query, params)]

    def get_postmortem(self, postmortem_id: str) -> Optional[Dict]:
        pid = as_uuid(postmortem_id)
        if pid is None:
            return None
        row = pool.q1(self._PM_SELECT + "WHERE id = %s", (pid,))
        return self._to_postmortem(row) if row else None

    # ------------------------------------------------------------------
    # public status history
    # ------------------------------------------------------------------
    def record_status_sample(self, component_id: str, date_bucket: str, name: str,
                             healthy: bool, expires_at: int = None) -> None:
        pool.exec_(
            "INSERT INTO status_history_days (component_id, date_bucket, name, sample_count, healthy_count) "
            "VALUES (%s, %s::date, %s, 1, %s) ON CONFLICT (component_id, date_bucket) DO UPDATE SET "
            "sample_count = status_history_days.sample_count + 1, "
            "healthy_count = status_history_days.healthy_count + EXCLUDED.healthy_count, "
            "name = EXCLUDED.name, updated_at = now()",
            (component_id, date_bucket, name, 1 if healthy else 0),
        )

    def get_status_history(self, component_ids: List[str], since: Optional[str] = None) -> Dict[str, List[Dict]]:
        rows = pool.q(
            "SELECT component_id, date_bucket::text AS date_bucket, name, sample_count, healthy_count "
            "FROM status_history_days WHERE component_id = ANY(%s) AND (%s::date IS NULL OR date_bucket >= %s::date) "
            "ORDER BY date_bucket", (list(component_ids), since, since))
        result: Dict[str, List[Dict]] = {cid: [] for cid in component_ids}
        for r in rows:
            result.setdefault(r["component_id"], []).append(dict(r))
        return result

    # ------------------------------------------------------------------
    # threat intel
    # ------------------------------------------------------------------
    def record_threat_hit(self, rule_id: str, bucket: str, attack_type: str, tenant_hash: str,
                          expires_at: int = None, updated_at: str = None) -> None:
        """+1 the (rule, hour) counter and add the tenant hash, atomically."""
        with pool.transaction():
            pool.exec_(
                "INSERT INTO threat_patterns (rule_id, bucket_start, attack_type, hit_count, updated_at) "
                "VALUES (%s, to_timestamp(%s, 'YYYYMMDDHH24')::timestamp AT TIME ZONE 'UTC', %s, 1, "
                "COALESCE(%s, now())) ON CONFLICT (rule_id, bucket_start) DO UPDATE SET "
                "hit_count = threat_patterns.hit_count + 1, attack_type = EXCLUDED.attack_type, "
                "updated_at = EXCLUDED.updated_at",
                (str(rule_id), bucket, attack_type, parse_ts(updated_at)),
            )
            pool.exec_(
                "INSERT INTO threat_pattern_contributors (rule_id, bucket_start, tenant_hash) "
                "VALUES (%s, to_timestamp(%s, 'YYYYMMDDHH24')::timestamp AT TIME ZONE 'UTC', %s) "
                "ON CONFLICT DO NOTHING", (str(rule_id), bucket, tenant_hash))

    def list_threat_patterns(self) -> List[Dict]:
        rows = pool.q(
            "SELECT p.rule_id, p.attack_type, to_char(p.bucket_start AT TIME ZONE 'UTC', 'YYYYMMDDHH24') AS time_bucket, "
            "p.hit_count, p.updated_at, COALESCE((SELECT array_agg(c.tenant_hash) FROM threat_pattern_contributors c "
            "WHERE c.rule_id = p.rule_id AND c.bucket_start = p.bucket_start), '{}') AS tenant_hashes "
            "FROM threat_patterns p ORDER BY p.bucket_start")
        return [{"pattern_key": f"{r['rule_id']}#{r['time_bucket']}", "rule_id": r["rule_id"],
                 "attack_type": r["attack_type"], "time_bucket": r["time_bucket"],
                 "hit_count": int(r["hit_count"]), "tenant_hashes": set(r["tenant_hashes"]),
                 "updated_at": iso_offset(r["updated_at"])} for r in rows]

    # ------------------------------------------------------------------
    # audit log (append-only)
    # ------------------------------------------------------------------
    def put_audit_event(self, item: Dict) -> None:
        """INSERT on the open transaction's connection when there is one, so
        the audit row commits or rolls back with the change it records.
        Errors propagate (fail-closed)."""
        from psycopg.types.json import Jsonb
        pool.exec_(
            "INSERT INTO audit_logs (event_id, scope_id, occurred_at, actor_user_id, actor_username, action, "
            "summary, details) VALUES (%s, %s, COALESCE(%s, now()), %s, %s, %s, %s, %s)",
            (item["event_id"], str(item["scope_id"]), parse_ts(item.get("timestamp")),
             as_uuid(item.get("actor_user_id")), item.get("actor_username") or "", item["action"],
             item.get("summary") or "", Jsonb(item.get("details") or {})),
        )

    def query_audit_events(self, scope_id: str) -> List[Dict]:
        rows = pool.q("SELECT * FROM audit_logs WHERE scope_id = %s ORDER BY event_id DESC", (str(scope_id),))
        return [{"scope_id": r["scope_id"], "event_id": r["event_id"], "timestamp": iso_offset(r["occurred_at"]),
                 "actor_user_id": str(r["actor_user_id"]) if r["actor_user_id"] else "",
                 "actor_username": r["actor_username"], "action": r["action"], "summary": r["summary"],
                 "details": r["details"]} for r in rows]

    # ------------------------------------------------------------------
    # BOLA policies
    # ------------------------------------------------------------------
    def list_bola_policies(self) -> List[Dict]:
        rows = pool.q("SELECT * FROM bola_policies ORDER BY priority, id")
        return [{"id": r["id"], "type": "bola_policy", "name": r["name"], "path_pattern": r["path_pattern"],
                 "claim_key": r["claim_key"], "resource_type": r["resource_type"], "action": r["action"],
                 "allow_admin": bool(r["allow_admin"]), "description": r["description"],
                 "enabled": bool(r["enabled"]), "methods": list(r["methods"]), "priority": int(r["priority"]),
                 "updated_at": str(int(r["updated_at"].timestamp()))} for r in rows]

    def put_bola_policy(self, item: Dict) -> None:
        methods = item.get("methods") or ["ALL"]
        if isinstance(methods, str):
            methods = [methods]
        updated = item.get("updated_at")
        pool.exec_(
            "INSERT INTO bola_policies (id, name, path_pattern, claim_key, resource_type, action, allow_admin, "
            "description, enabled, methods, priority, updated_at) VALUES (%s, %s, %s, %s, %s, upper(%s), %s, %s, %s, "
            "%s, %s, COALESCE(to_timestamp(%s::bigint), now())) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "
            "path_pattern = EXCLUDED.path_pattern, claim_key = EXCLUDED.claim_key, "
            "resource_type = EXCLUDED.resource_type, action = EXCLUDED.action, allow_admin = EXCLUDED.allow_admin, "
            "description = EXCLUDED.description, enabled = EXCLUDED.enabled, methods = EXCLUDED.methods, "
            "priority = EXCLUDED.priority, updated_at = EXCLUDED.updated_at",
            (str(item["id"]), item.get("name") or "Custom BOLA Policy", item["path_pattern"],
             item.get("claim_key") or "sub", item.get("resource_type") or "user_id", item.get("action") or "BLOCK",
             bool(item.get("allow_admin", True)), item.get("description") or "", bool(item.get("enabled", True)),
             [str(m).upper() for m in methods], int(item.get("priority", 100)),
             str(int(float(updated))) if updated not in (None, "") else None),
        )

    def delete_bola_policy(self, policy_id: str) -> None:
        pool.exec_("DELETE FROM bola_policies WHERE id = %s", (str(policy_id),))


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


# ----------------------------------------------------------------------
# ML / CVE rule proposals (waf.pending_rules), used by ml_rule_service.py
# ----------------------------------------------------------------------
from db.values import iso_z_s  # noqa: E402

_PENDING_TEXT = ("pattern", "variable", "attack_type", "severity", "secrule_template", "source_url",
                 "source_method", "created_by", "origin_label", "generator", "detector")
# Any ModSecurity id handed out by approve is above this (ml_rule_service START_RULE_ID - 1).
_FIRST_ML_RULE_ID_MINUS_ONE = 1000499
# pg_advisory_xact_lock key serialising rule-id allocation across approvers.
_APPROVE_LOCK_KEY = 7_420_001


class PgPendingRuleRepository:
    """Rule dicts keep the DynamoDB-era shape: '' (not None) for cve_id /
    dedup_key / origin_id, times as '%Y-%m-%dT%H:%M:%SZ'."""

    @staticmethod
    def to_rule(row: Optional[dict]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        rule: Dict[str, Any] = {
            "rule_id": str(row["rule_id"]),
            "created_at": iso_z_s(row["created_at"]),
            "status": row["status"],
            **{k: row[k] for k in _PENDING_TEXT},
            "cve_id": row["cve_id"] or "",
            "origin_id": str(row["origin_id"]) if row["origin_id"] else "",
            "dedup_key": row["dedup_key"] or "",
            "hit_count": int(row["hit_count"]),
            "examples": list(row["examples"] or []),
            "last_seen_at": iso_z_s(row["last_seen_at"]),
        }
        if row.get("backtest") is not None:
            rule["backtest"] = row["backtest"]
        for key in ("reviewed_by", "reject_reason"):
            if row.get(key) is not None:
                rule[key] = row[key]
        if row.get("reviewed_at") is not None:
            rule["reviewed_at"] = iso_z_s(row["reviewed_at"])
        if row.get("deployed_rule_id") is not None:
            rule["deployed_rule_id"] = int(row["deployed_rule_id"])
        return rule

    def create(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Insert a proposal. A pending row with the same dedup_key absorbs
        it instead (hit_count+1, newest examples first, at most 5) -- one
        statement, so two concurrent proposals cannot both insert."""
        from psycopg.types.json import Jsonb
        row = pool.q1(
            "INSERT INTO pending_rules (rule_id, created_at, status, pattern, variable, attack_type, severity, "
            "secrule_template, source_url, source_method, created_by, cve_id, origin_id, origin_label, generator, "
            "detector, dedup_key, hit_count, examples, last_seen_at) VALUES (%(rule_id)s, COALESCE(%(created_at)s, now()), "
            "'pending', %(pattern)s, %(variable)s, %(attack_type)s, %(severity)s, %(secrule_template)s, %(source_url)s, "
            "%(source_method)s, %(created_by)s, %(cve_id)s, (SELECT id FROM origins WHERE id = %(origin_id)s), "
            "%(origin_label)s, %(generator)s, %(detector)s, %(dedup_key)s, 1, %(examples)s, COALESCE(%(created_at)s, now())) "
            "ON CONFLICT (dedup_key) WHERE status = 'pending' AND dedup_key IS NOT NULL DO UPDATE SET "
            "hit_count = pending_rules.hit_count + 1, "
            "examples = (SELECT COALESCE(jsonb_agg(e ORDER BY n), '[]'::jsonb) FROM "
            "  jsonb_array_elements(EXCLUDED.examples || pending_rules.examples) WITH ORDINALITY AS t(e, n) WHERE n <= 5), "
            "last_seen_at = EXCLUDED.last_seen_at RETURNING *",
            {
                "rule_id": as_uuid(item.get("rule_id")),
                "created_at": parse_ts(item.get("created_at")),
                **{k: str(item.get(k) or "") for k in _PENDING_TEXT},
                "cve_id": item.get("cve_id") or None,
                "origin_id": as_uuid(item.get("origin_id")),
                "dedup_key": item.get("dedup_key") or None,
                "examples": Jsonb(list(item.get("examples") or [])[:5]),
            },
        )
        return self.to_rule(row)

    def get(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rid = as_uuid(rule_id)
        if rid is None:
            return None
        return self.to_rule(pool.q1("SELECT * FROM pending_rules WHERE rule_id = %s", (rid,)))

    def find_pending_by_dedup_key(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        if not dedup_key:
            return None
        return self.to_rule(pool.q1("SELECT * FROM pending_rules WHERE status = 'pending' AND dedup_key = %s",
                                    (dedup_key,)))

    def list(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            rows = pool.q("SELECT * FROM pending_rules WHERE status = %s ORDER BY created_at DESC", (status,))
        else:
            rows = pool.q("SELECT * FROM pending_rules ORDER BY created_at DESC")
        return [self.to_rule(r) for r in rows]

    def record_hit(self, rule_id: str, example: Dict[str, Any], seen_at: str) -> Optional[Dict[str, Any]]:
        from psycopg.types.json import Jsonb
        rid = as_uuid(rule_id)
        if rid is None:
            return None
        return self.to_rule(pool.q1(
            "UPDATE pending_rules SET hit_count = hit_count + 1, last_seen_at = %s, "
            "examples = (SELECT COALESCE(jsonb_agg(e ORDER BY n), '[]'::jsonb) FROM "
            "  jsonb_array_elements(%s || examples) WITH ORDINALITY AS t(e, n) WHERE n <= 5) "
            "WHERE rule_id = %s RETURNING *", (parse_ts(seen_at), Jsonb([example]), rid)))

    def save_backtest(self, rule_id: str, result: Dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb
        rid = as_uuid(rule_id)
        if rid is not None:
            pool.exec_("UPDATE pending_rules SET backtest = %s WHERE rule_id = %s", (Jsonb(result), rid))

    def reserve_approval(self, rule_id: str, approved_by: str, max_file_rule_id: int) -> Dict[str, Any]:
        """Inside the caller's transaction: lock, check pending, allocate the
        next ModSecurity id above both the files on disk and every id ever
        recorded, and mark the rule approved. Raises ValueError like the
        DynamoDB path did."""
        rid = as_uuid(rule_id)
        if rid is None:
            raise ValueError("Rule not found")
        pool.exec_("SELECT pg_advisory_xact_lock(%s)", (_APPROVE_LOCK_KEY,))
        row = pool.q1("SELECT * FROM pending_rules WHERE rule_id = %s FOR UPDATE", (rid,))
        if not row:
            raise ValueError("Rule not found")
        if row["status"] != "pending":
            raise ValueError(f"Rule is already {row['status']}")
        top = pool.q1("SELECT max(deployed_rule_id) AS m FROM pending_rules")["m"] or 0
        new_id = max(int(max_file_rule_id), int(top), _FIRST_ML_RULE_ID_MINUS_ONE) + 1
        row = pool.q1("UPDATE pending_rules SET status = 'approved', reviewed_by = %s, reviewed_at = now(), "
                      "deployed_rule_id = %s WHERE rule_id = %s RETURNING *", (approved_by, new_id, rid))
        return self.to_rule(row)

    def undo_approval(self, rule_id: str, deployed_rule_id: int) -> None:
        """Compensation when the deploy after commit failed."""
        pool.exec_("UPDATE pending_rules SET status = 'pending', deployed_rule_id = NULL, reviewed_by = NULL, "
                   "reviewed_at = NULL WHERE rule_id = %s AND deployed_rule_id = %s",
                   (as_uuid(rule_id), int(deployed_rule_id)))

    def reject(self, rule_id: str, rejected_by: str, reason: str) -> Dict[str, Any]:
        rid = as_uuid(rule_id)
        row = pool.q1("UPDATE pending_rules SET status = 'rejected', reviewed_by = %s, reviewed_at = now(), "
                      "reject_reason = %s WHERE rule_id = %s AND status = 'pending' RETURNING *",
                      (rejected_by, reason, rid)) if rid else None
        if row:
            return self.to_rule(row)
        existing = self.get(rule_id)
        if not existing:
            raise ValueError("Rule not found")
        raise ValueError(f"Rule is already {existing.get('status')}")

    def reject_legacy(self, rejected_by: str, reason: str) -> Dict[str, int]:
        """Reject every pending rf-regex rule; one statement, so a rule
        approved meanwhile (no longer pending) is simply not matched."""
        pending = pool.q1("SELECT count(*) AS n FROM pending_rules WHERE status = 'pending' AND generator = 'rf-regex'")["n"]
        rejected = pool.exec_("UPDATE pending_rules SET status = 'rejected', reviewed_by = %s, reviewed_at = now(), "
                              "reject_reason = %s WHERE status = 'pending' AND generator = 'rf-regex'",
                              (rejected_by, reason))
        return {"rejected": rejected, "skipped": max(int(pending) - rejected, 0)}

    def delete(self, rule_id: str) -> None:
        rid = as_uuid(rule_id)
        if rid is not None:
            pool.exec_("DELETE FROM pending_rules WHERE rule_id = %s", (rid,))


# ----------------------------------------------------------------------
# threshold proposals (waf.threshold_proposals)
# ----------------------------------------------------------------------
_THRESHOLD_OPTIONAL_TEXT = ("approved_by", "rejected_by", "reject_reason", "rolled_back_by")
_THRESHOLD_OPTIONAL_TS = ("approved_at", "rejected_at", "rolled_back_at")


class PgThresholdProposalRepository:
    @staticmethod
    def to_proposal(row: Optional[dict]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        p: Dict[str, Any] = {
            "proposal_id": str(row["proposal_id"]), "status": row["status"],
            "current_threshold": row["current_threshold"], "proposed_threshold": row["proposed_threshold"],
            "lookback_hours": row["lookback_hours"], "reason": row["reason"], "evidence": row["evidence"],
            "created_by": row["created_by"], "created_at": iso_z_s(row["created_at"]),
        }
        for key in _THRESHOLD_OPTIONAL_TEXT:
            if row.get(key) is not None:
                p[key] = row[key]
        for key in _THRESHOLD_OPTIONAL_TS:
            if row.get(key) is not None:
                p[key] = iso_z_s(row[key])
        if row.get("previous_threshold") is not None:
            p["previous_threshold"] = row["previous_threshold"]
        return p

    def create(self, proposal: Dict[str, Any], created_by: str) -> Dict[str, Any]:
        from psycopg.types.json import Jsonb
        row = pool.q1(
            "INSERT INTO threshold_proposals (current_threshold, proposed_threshold, lookback_hours, reason, "
            "evidence, created_by) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
            (int(proposal["current_threshold"]), int(proposal["proposed_threshold"]),
             int(proposal["lookback_hours"]), proposal["reason"], Jsonb(proposal.get("evidence") or {}), created_by))
        return self.to_proposal(row)

    def get(self, proposal_id: str) -> Optional[Dict[str, Any]]:
        pid = as_uuid(proposal_id)
        if pid is None:
            return None
        return self.to_proposal(pool.q1("SELECT * FROM threshold_proposals WHERE proposal_id = %s", (pid,)))

    def list(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            rows = pool.q("SELECT * FROM threshold_proposals WHERE status = %s ORDER BY created_at DESC", (status,))
        else:
            rows = pool.q("SELECT * FROM threshold_proposals ORDER BY created_at DESC")
        return [self.to_proposal(r) for r in rows]

    def transition(self, proposal_id: str, from_status: str, sets: str, params: tuple) -> Optional[Dict[str, Any]]:
        """UPDATE ... WHERE status = from_status; None when it was not in that state."""
        pid = as_uuid(proposal_id)
        if pid is None:
            return None
        return self.to_proposal(pool.q1(
            f"UPDATE threshold_proposals SET {sets} WHERE proposal_id = %s AND status = %s RETURNING *",
            (*params, pid, from_status)))


# ----------------------------------------------------------------------
# global IP rules and rate-limit rules (were SQLite data/*.db)
# ----------------------------------------------------------------------
_IP_SELECT = ("SELECT id, abbrev(ip) AS ip, rule_type, reason, added_by, created_at, expires_at, hits, source "
              "FROM ip_rules ")


class PgIPRuleRepository:
    """Rows keep the SQLite shape: ip as text ('1.2.3.4', '10.0.0.0/24'),
    created_at / expires_at as epoch ints."""

    @staticmethod
    def to_rule(row: dict) -> Dict[str, Any]:
        rule = dict(row)
        rule["created_at"] = epoch_int(row["created_at"])
        rule["expires_at"] = epoch_int(row["expires_at"]) if row["expires_at"] else None
        return rule

    def delete_expired(self) -> int:
        return pool.exec_("DELETE FROM ip_rules WHERE expires_at IS NOT NULL AND expires_at < now()")

    def ips(self, rule_type: str) -> List[str]:
        return [r["ip"] for r in pool.q("SELECT abbrev(ip) AS ip FROM ip_rules WHERE rule_type = %s "
                                        "ORDER BY created_at DESC", (rule_type,))]

    def list(self, rule_type: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if rule_type and rule_type.lower() != "all":
            clauses.append("rule_type = %s")
            params.append(rule_type.lower())
        if search:
            like = f"%{search.strip()}%"
            clauses.append("(abbrev(ip) ILIKE %s OR reason ILIKE %s OR added_by ILIKE %s)")
            params.extend([like, like, like])
        where = ("WHERE " + " AND ".join(clauses) + " ") if clauses else ""
        return [self.to_rule(r) for r in pool.q(_IP_SELECT + where + "ORDER BY created_at DESC", params)]

    def upsert(self, ip: str, rule_type: str, reason: str, added_by: str,
               expires_at: Optional[int], source: str) -> None:
        """INSERT OR REPLACE semantics: the same address keeps its row id."""
        pool.exec_(
            "INSERT INTO ip_rules (ip, rule_type, reason, added_by, created_at, expires_at, source) "
            "VALUES (%s::inet, %s, %s, %s, now(), %s, %s) ON CONFLICT (ip) DO UPDATE SET "
            "rule_type = EXCLUDED.rule_type, reason = EXCLUDED.reason, added_by = EXCLUDED.added_by, "
            "created_at = now(), expires_at = EXCLUDED.expires_at, source = EXCLUDED.source",
            (ip, rule_type, reason, added_by, from_epoch(expires_at), source))

    def delete(self, ips: List[str]) -> int:
        if not ips:
            return 0
        return pool.exec_("DELETE FROM ip_rules WHERE ip = ANY(%s::inet[])", (list(ips),))

    def stats(self) -> Dict[str, int]:
        r = pool.q1("SELECT count(*) FILTER (WHERE rule_type = 'block') AS blocked, "
                    "count(*) FILTER (WHERE rule_type = 'allow') AS allowed, "
                    "count(*) FILTER (WHERE rule_type = 'block' AND expires_at IS NOT NULL) AS temp FROM ip_rules")
        return {"total_blocked": r["blocked"], "total_allowed": r["allowed"], "temp_banned": r["temp"],
                "permanent_blocked": r["blocked"] - r["temp"]}


_RATE_COLUMNS = ("name", "path_pattern", "method", "limit_count", "window_seconds", "burst", "action", "enabled")


class PgRateLimitRepository:
    """Rows keep the SQLite shape: enabled as int 1/0, created_at as epoch int."""

    @staticmethod
    def to_rule(row: Optional[dict]) -> Optional[Dict[str, Any]]:
        if not row:
            return None
        rule = dict(row)
        rule["enabled"] = 1 if row["enabled"] else 0
        rule["created_at"] = epoch_int(row["created_at"])
        return rule

    def list(self) -> List[Dict[str, Any]]:
        return [self.to_rule(r) for r in pool.q("SELECT * FROM rate_limit_rules ORDER BY created_at, id")]

    def add(self, rule_id: str, name: str, path_pattern: str, method: str, limit_count: int,
            window_seconds: int, burst: int, action: str) -> None:
        pool.exec_("INSERT INTO rate_limit_rules (id, name, path_pattern, method, limit_count, window_seconds, "
                   "burst, action, enabled) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, true)",
                   (rule_id, name, path_pattern, method.upper(), limit_count, window_seconds, burst, action))

    def update(self, rule_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        values = {}
        for key in _RATE_COLUMNS:
            if key in data:
                value = data[key]
                if key == "enabled":
                    value = bool(value)
                elif key == "method" and value is not None:
                    value = str(value).upper()
                values[key] = value
        if not values:
            return None
        query = sql.SQL("UPDATE rate_limit_rules SET {} WHERE id = %s RETURNING *").format(
            sql.SQL(", ").join(sql.SQL("{} = {}").format(sql.Identifier(k), sql.Placeholder()) for k in values))
        return self.to_rule(pool.q1(query.as_string(), [*values.values(), rule_id]))

    def delete(self, rule_id: str) -> bool:
        return pool.exec_("DELETE FROM rate_limit_rules WHERE id = %s", (rule_id,)) > 0
