"""
Dynamic Deception Layer (WAF Honeypot) Service.
Handles attack classification, secure synthetic response generation,
strict anti-caching header enforcement, and fail-safe dual-sink audit logging.
"""

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.payload_normalizer import payload_normalizer
from services.pii_masker import pii_masker

logger = logging.getLogger("waf.deception")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackClassification:
    category: str
    template_id: str
    confidence: float

    def __iter__(self):
        return iter((self.category, self.template_id, self.confidence))


@dataclass(frozen=True)
class DeceptionResponse:
    status_code: int
    content_type: str
    body: str
    headers: Dict[str, str]
    template_id: str
    category: str

    @property
    def content(self) -> str:
        return self.body

    @property
    def media_type(self) -> str:
        return self.content_type


@dataclass(frozen=True)
class DeceptionLogEvent:
    # R6.1 Mandatory Fields
    request_id: str             # Transaction ID from Nginx (X-Request-ID) or UUID4
    timestamp: int              # Integer Unix epoch timestamp
    rule_id: str                # Matched rule ID
    attack_category: str        # e.g., "Path Traversal (LFI)" or "SQL Injection (SQLi)"
    template_id: str            # e.g., "path_traversal", "sql_injection"
    response_status: int        # HTTP status code (always 200)
    execution_result: str       # "deceived"

    # Context & Network Metadata
    client_ip: str              # Client IP
    method: str                 # HTTP Method (GET, POST, etc.)
    url: str                    # Original requested URI (X-Original-URI)
    user_agent: str             # User-Agent string
    edge_node: str              # Edge node tag (e.g., "edge-th")
    latency_ms: float           # Response generation latency in ms
    body_bytes_sent: int        # Length of synthetic body in bytes
    datetime: str               # ISO-8601 UTC timestamp string

    # Telemetry Classification Flags
    alert: bool = True          # Always True for deception events
    severity: str = "CRITICAL"  # Threat severity level
    action: str = "DECEIVE"     # Action executed
    source: str = "deception"   # Telemetry source identifier
    host: str = ""              # Original Host header, for tenant attribution


# ---------------------------------------------------------------------------
# ReDoS-Safe Linear Signatures
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_REGEX = re.compile(
    r"(?i)("
    r"(?:\.\.[/\\])+|"
    r"/(?:etc|proc|sys|var|boot|windows|winnt)(?:/|\b)|"
    r"(?:etc[/\\]passwd|etc[/\\]shadow|etc[/\\]hosts|boot\.ini|win\.ini)|"
    r"php://(?:filter|input|memory)|file://|phar://"
    r")"
)

SQLI_REGEX = re.compile(
    r"(?i)("
    r"[\x27\x22\)]\s*(?:or|and)\s+[\(\x27\x22]*\w*[\)\x27\x22]*\s*=\s*[\(\x27\x22]*\w*[\)\x27\x22]*|"
    r"\bor\s+\d+=\d+|\band\s+\d+=\d+|"
    r"\bunion(?:\s+all)?\s+select\b|"
    r"\bselect\s+(?:\*|[\w,`\"\x27\.()]{1,150})\s+from\s+[\w`\"\x27\.]+\b|"
    r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\s+[\x27\x220-9:]+|"
    r"\bexec\s*(?:\(\s*)?xp_cmdshell\b|"
    r"\bdrop\s+table\b|"
    r"\binformation_schema\b|\bsys\.tables\b|\bpg_tables\b|"
    r"(?:--|#)(?:\s|$)|/\*[^*]{0,512}\*/"
    r")"
)


# ---------------------------------------------------------------------------
# Mandatory Anti-Cache & Security Headers
# ---------------------------------------------------------------------------

SECURE_DECEPTION_HEADERS: Dict[str, str] = {
    # Suppress all browser, intermediate proxy, and CDN caching
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, private, s-maxage=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Surrogate-Control": "no-store",
    "CDN-Cache-Control": "no-store",

    # MIME-sniffing & clickjacking defense
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",

    # Conceal backend server technology
    "Server": "nginx",
}


# ---------------------------------------------------------------------------
# Predefined In-Memory Synthetic Templates (Zero Leakage - Zero Disk/DB Reads)
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_TEMPLATE: str = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
    "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
    "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
    "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
    "messagebus:x:103:107::/nonexistent:/usr/sbin/nologin\n"
    "_apt:x:104:65534::/nonexistent:/usr/sbin/nologin\n"
    "admin:x:1000:1000:Administrator,,,:/home/admin:/bin/bash\n"
    "appuser:x:1001:1001:Application Service Account,,,:/home/appuser:/bin/sh\n"
    "secops:x:1002:1002:Security Operations,,,:/home/secops:/bin/bash\n"
    "postgres:x:1003:1003:PostgreSQL Database Server,,,:/var/lib/postgresql:/bin/bash\n"
    "deployer:x:1004:1004:CI/CD Deployment Service,,,:/home/deployer:/bin/bash\n"
)

SQLI_TEMPLATE: str = json.dumps(
    {
        "status": "success",
        "query_execution_time_ms": 14.2,
        "database": "production_app_db",
        "schema": {
            "tables": [
                {
                    "table_name": "app_users",
                    "columns": [
                        {"name": "user_id", "type": "INT", "primary_key": True},
                        {"name": "username", "type": "VARCHAR(64)", "unique": True},
                        {"name": "email", "type": "VARCHAR(255)", "unique": True},
                        {"name": "role", "type": "VARCHAR(32)"},
                        {"name": "password_hash", "type": "VARCHAR(128)"},
                        {"name": "mfa_enabled", "type": "BOOLEAN"},
                        {"name": "is_active", "type": "BOOLEAN"},
                        {"name": "created_at", "type": "TIMESTAMP"},
                    ],
                    "rows": [
                        {
                            "user_id": 101,
                            "username": "sysadmin_svc",
                            "email": "sysadmin@corp.internal",
                            "role": "SuperAdmin",
                            "password_hash": "$pbkdf2-sha256$29000$dummySaltValue$dummySyntheticHashKx9281aZ0",
                            "mfa_enabled": True,
                            "is_active": True,
                            "created_at": "2024-01-15T08:30:00Z",
                        },
                        {
                            "user_id": 102,
                            "username": "billing_auditor",
                            "email": "auditor@corp.internal",
                            "role": "FinanceAuditor",
                            "password_hash": "$pbkdf2-sha256$29000$dummySaltValue$dummySyntheticHashLm8312bY1",
                            "mfa_enabled": True,
                            "is_active": True,
                            "created_at": "2024-02-01T10:15:00Z",
                        },
                        {
                            "user_id": 103,
                            "username": "customer_support",
                            "email": "support_lead@corp.internal",
                            "role": "SupportStaff",
                            "password_hash": "$pbkdf2-sha256$29000$dummySaltValue$dummySyntheticHashPn4491cW2",
                            "mfa_enabled": False,
                            "is_active": True,
                            "created_at": "2024-03-10T14:45:00Z",
                        },
                    ],
                },
                {
                    "table_name": "system_config",
                    "columns": [
                        {"name": "config_key", "type": "VARCHAR(64)", "primary_key": True},
                        {"name": "config_value", "type": "VARCHAR(255)"},
                        {"name": "is_encrypted", "type": "BOOLEAN"},
                    ],
                    "rows": [
                        {
                            "config_key": "auth_provider",
                            "config_value": "internal_oauth2",
                            "is_encrypted": False,
                        },
                        {
                            "config_key": "session_ttl_seconds",
                            "config_value": "86400",
                            "is_encrypted": False,
                        },
                        {
                            "config_key": "maintenance_window",
                            "config_value": "SUN_0200_UTC",
                            "is_encrypted": False,
                        },
                    ],
                },
            ],
            "total_records": 6,
            "version": "PostgreSQL 15.4 (Ubuntu 15.4-1.pgdg22.04+1)",
        },
    },
    indent=2,
)


TEMPLATES_CATALOG: Dict[str, Dict[str, Any]] = {
    "path_traversal": {
        "id": "path_traversal",
        "name": "Fabricated Unix System File (/etc/passwd)",
        "attack_category": "Path Traversal (LFI)",
        "content_type": "text/plain",
        "status_code": 200,
        "description": "Returns a realistic Unix /etc/passwd system file containing mock service accounts.",
        "sample_preview": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon...",
        "body": PATH_TRAVERSAL_TEMPLATE,
    },
    "sql_injection": {
        "id": "sql_injection",
        "name": "Fabricated Database Schema & Rows (JSON)",
        "attack_category": "SQL Injection (SQLi)",
        "content_type": "application/json",
        "status_code": 200,
        "description": "Returns a mock database schema with tables, columns, and synthetic credential rows.",
        "sample_preview": '{"status": "success", "database": "production_app_db", ...}',
        "body": SQLI_TEMPLATE,
    },
}


# ---------------------------------------------------------------------------
# Deception Service Class
# ---------------------------------------------------------------------------

class DeceptionService:
    """Core deception engine responsible for classification, templating, and fail-safe logging."""

    def __init__(
        self,
        ch_service: Optional[ClickHouseService] = None,
        db_service: Optional[DynamoDBService] = None,
    ):
        self._ch = ch_service
        self._db = db_service

    @property
    def ch(self) -> ClickHouseService:
        if self._ch is None:
            self._ch = ClickHouseService()
        return self._ch

    @ch.setter
    def ch(self, val: Any):
        self._ch = val

    @property
    def db(self) -> DynamoDBService:
        if self._db is None:
            self._db = DynamoDBService()
        return self._db

    @db.setter
    def db(self, val: Any):
        self._db = val

    def classify_attack(
        self,
        uri: str = "/",
        body: str = "",
        template_hint: Optional[str] = None,
    ) -> AttackClassification:
        """
        3-Tier attack classification:
        1. Explicit rule/header hint ('path_traversal', 'sql_injection').
        2. Normalized payload inspection (ReDoS-safe regex across raw and normalized tokens).
        3. Contextual heuristic fallback (API vs static/resource patterns).
        """
        # Tier 1: Explicit hint
        hint_clean = (template_hint or "").strip().lower()
        if hint_clean in ("path_traversal", "traversal", "lfi"):
            return AttackClassification("Path Traversal (LFI)", "path_traversal", 1.0)
        if hint_clean in ("sql_injection", "sqli"):
            return AttackClassification("SQL Injection (SQLi)", "sql_injection", 1.0)

        # Bounded inputs to prevent ReDoS / CPU exhaustion
        safe_uri = (uri or "")[:4096]
        safe_body = (body or "")[:4096]

        # Normalized representations
        normalized_uri = payload_normalizer.normalize_string(safe_uri)
        normalized_body = payload_normalizer.normalize_string(safe_body)

        # Candidate corpus list: test against both raw and normalized vectors
        corpus_list = [
            safe_uri,
            safe_body,
            normalized_uri,
            normalized_body,
        ]

        # Tier 2: Signature pattern matching
        # Check Path Traversal
        for corpus in corpus_list:
            if corpus and PATH_TRAVERSAL_REGEX.search(corpus):
                return AttackClassification("Path Traversal (LFI)", "path_traversal", 0.95)

        # Check SQL Injection
        for corpus in corpus_list:
            if corpus and SQLI_REGEX.search(corpus):
                return AttackClassification("SQL Injection (SQLi)", "sql_injection", 0.95)

        # Tier 3: Contextual heuristic fallback
        uri_lower = safe_uri.lower()
        body_lower = safe_body.lower()
        check_corpus = uri_lower + " " + body_lower

        # Heuristic SQLi: API/REST routes, database query param keys (form & JSON)
        api_indicators = ["/api/", "/rest/", "/v1/", "/v2/", "/graphql", "/auth", "/login", "/user"]
        query_param_indicators = [
            "q=", "query=", "search=", "id=", "filter=", "user=", "name=", "select=",
            '"q":', '"query":', '"search":', '"id":', '"filter":', '"user":', '"name":', '"select":'
        ]
        if any(ind in check_corpus for ind in api_indicators) or any(ind in check_corpus for ind in query_param_indicators):
            return AttackClassification("SQL Injection (SQLi)", "sql_injection", 0.70)

        # Heuristic Path Traversal: file extensions, download paths
        file_ext_indicators = [".php", ".asp", ".aspx", ".jsp", ".txt", ".log", ".conf", ".ini", ".zip", ".tar", ".gz", "/download", "/files/", "/static/"]
        if any(ext in uri_lower for ext in file_ext_indicators):
            return AttackClassification("Path Traversal (LFI)", "path_traversal", 0.70)

        # General default fallback: Path Traversal (believable Unix system file)
        return AttackClassification("Path Traversal (LFI)", "path_traversal", 0.50)

    def generate_response(
        self,
        uri: str = "/",
        method: str = "GET",
        body: str = "",
        client_ip: str = "127.0.0.1",
        request_id: str = "",
        rule_id: Optional[str] = None,
        template_hint: Optional[str] = None,
        template_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> DeceptionResponse:
        """
        Generates a contextual synthetic deception response based on attack classification.
        Guarantees HTTP status 200, strictly synthetic content, and anti-caching headers.
        """
        active_hint = template_hint or template_id
        classification = self.classify_attack(uri=uri, body=body, template_hint=active_hint)
        resolved_template_id = classification.template_id

        template_meta = TEMPLATES_CATALOG.get(resolved_template_id, TEMPLATES_CATALOG["path_traversal"])

        response_headers = dict(SECURE_DECEPTION_HEADERS)
        if request_id:
            response_headers["X-Request-ID"] = request_id

        return DeceptionResponse(
            status_code=template_meta["status_code"],
            content_type=template_meta["content_type"],
            body=template_meta["body"],
            headers=response_headers,
            template_id=resolved_template_id,
            category=classification.category,
        )

    def handle_deception(
        self,
        request_id: str = "",
        client_ip: str = "127.0.0.1",
        uri: str = "/",
        method: str = "GET",
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
        rule_id: Optional[str] = None,
        template_hint: Optional[str] = None,
    ) -> DeceptionResponse:
        """Convenience alias matching Explorer design for generating responses."""
        return self.generate_response(
            uri=uri,
            method=method,
            body=body,
            client_ip=client_ip,
            request_id=request_id,
            rule_id=rule_id,
            template_hint=template_hint,
            headers=headers,
        )

    def get_fallback_response(self, request_id: str = "") -> DeceptionResponse:
        """
        Fail-safe static response used if an unexpected error occurs during classification.
        Guarantees zero origin leakage and prevents 500 error disclosure.
        """
        response_headers = dict(SECURE_DECEPTION_HEADERS)
        if request_id:
            response_headers["X-Request-ID"] = request_id

        return DeceptionResponse(
            status_code=200,
            content_type="text/plain",
            body=PATH_TRAVERSAL_TEMPLATE,
            headers=response_headers,
            template_id="path_traversal",
            category="Path Traversal (LFI)",
        )

    def list_templates(self) -> List[Dict[str, Any]]:
        """Returns metadata catalog of all registered deception templates."""
        return [
            {
                "id": t["id"],
                "name": t["name"],
                "attack_category": t["attack_category"],
                "content_type": t["content_type"],
                "status_code": t["status_code"],
                "description": t["description"],
                "sample_preview": t["sample_preview"],
            }
            for t in TEMPLATES_CATALOG.values()
        ]

    def simulate(
        self,
        uri: str,
        method: str = "GET",
        body: str = "",
        rule_id: Optional[str] = None,
        template_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dry-run simulation for administrative inspection and UI preview."""
        classification = self.classify_attack(uri=uri, body=body, template_hint=template_id)
        resp = self.generate_response(
            uri=uri,
            method=method,
            body=body,
            rule_id=rule_id,
            template_hint=template_id,
        )
        return {
            "attack_category": classification.category,
            "template_id": classification.template_id,
            "confidence": classification.confidence,
            "response": {
                "status_code": resp.status_code,
                "content_type": resp.content_type,
                "headers": resp.headers,
                "body_preview": resp.body[:300] + ("..." if len(resp.body) > 300 else ""),
            },
        }

    # -----------------------------------------------------------------------
    # Resilient Audit Logging (R6.1 - R6.4)
    # -----------------------------------------------------------------------

    def log_deception_event(self, event: DeceptionLogEvent) -> bool:
        """
        Fail-safe structured audit logger for deception events.
        Guarantees that ANY logging failure (database crash, network partition,
        schema mismatch, timeout) is caught, logged, and swallowed without
        interrupting HTTP response flow or leaking to origin.
        """
        try:
            # 1. Sanitize untrusted values (R6.3)
            raw_url = event.url[:2048] if event.url else "/"
            sanitized_url, _ = pii_masker.mask_text(raw_url)
            sanitized_ua = event.user_agent[:256] if event.user_agent else ""
            clean_ip = event.client_ip.split(",")[0].strip() if event.client_ip else "unknown"

            # 2. ClickHouse Sink (Primary Analytics)
            with _CH_WRITE_LOCK:
                self._save_to_clickhouse(event, sanitized_url, sanitized_ua, clean_ip)

            # 3. DynamoDB Sink (Dashboard & Real-Time Alerts)
            self._save_to_dynamodb(event, sanitized_url, sanitized_ua, clean_ip)

            return True

        except Exception as exc:
            # R6.4: Shield - fail-safe isolation
            logger.error("Deception audit logging failed (fail-safe isolated): %s", exc, exc_info=True)
            return False

    def _save_to_clickhouse(
        self,
        event: DeceptionLogEvent,
        sanitized_url: str,
        sanitized_ua: str,
        clean_ip: str,
    ):
        """Dispatches event to ClickHouse access_logs and security_audit_logs."""
        if not self.ch or not getattr(self.ch, "connected", False):
            return

        try:
            # 2a. Ingest into access_logs table
            access_entry = {
                "request_id": event.request_id,
                "datetime": event.datetime,
                "timestamp": event.timestamp,
                "ip": clean_ip,
                "method": event.method,
                "url": sanitized_url,
                "status": event.response_status,
                "latency_ms": event.latency_ms,
                "user_agent": sanitized_ua,
                "edge_node": event.edge_node or "edge-th",
                "alert": 1 if event.alert else 0,
                "attack_type": f"Deception: {event.attack_category}",
                "rule_id": event.rule_id or "DECEPTION-ENGINE",
                "body_bytes_sent": event.body_bytes_sent,
                "http_referer": "",
                "host": event.host,
            }
            self.ch.save_log("access_logs", access_entry)

            # 2b. Ingest into security_audit_logs table
            audit_entry = {
                "request_id": event.request_id,
                "timestamp": event.datetime,
                "client_ip": clean_ip,
                "rule_id": event.rule_id or "DECEPTION-ENGINE",
                "message": f"Honeypot Deception served synthetic {event.template_id} for {event.attack_category}",
                "severity": event.severity,
                "action": event.action,
                "edge_node": event.edge_node or "edge-th",
            }
            # Attempt via save_log if supported, or directly through client
            saved = False
            try:
                saved = self.ch.save_log("security_audit_logs", audit_entry)
            except Exception:
                saved = False

            if not saved and hasattr(self.ch, "client") and self.ch.client:
                try:
                    log_uuid = uuid.UUID(str(event.request_id))
                except Exception:
                    log_uuid = uuid.uuid4()
                row = [
                    log_uuid,
                    datetime.utcnow(),
                    clean_ip,
                    str(event.rule_id or "DECEPTION-ENGINE"),
                    audit_entry["message"],
                    event.severity,
                    event.action,
                    event.edge_node or "edge-th",
                ]
                self.ch.client.insert(
                    "security_audit_logs",
                    [row],
                    column_names=[
                        "id", "timestamp", "client_ip", "rule_id", "message", "severity", "action", "edge_node"
                    ],
                )

        except Exception as ch_err:
            logger.warning("ClickHouse deception log write error (non-blocking): %s", ch_err)

    def _save_to_dynamodb(
        self,
        event: DeceptionLogEvent,
        sanitized_url: str,
        sanitized_ua: str,
        clean_ip: str,
    ):
        """Dispatches event to DynamoDB waf_logs table."""
        if not self.db:
            return

        try:
            dynamo_entry = {
                "user_id": "default-user",
                "log_id": str(uuid.uuid4()),
                "request_id": event.request_id,
                "timestamp": event.timestamp,
                "datetime": event.datetime,
                "ip": clean_ip,
                "method": event.method,
                "url": sanitized_url,
                "status": event.response_status,
                "action": event.action,
                "attack_category": event.attack_category,
                "attack_type": f"Deception: {event.attack_category}",
                "template_id": event.template_id,
                "rule_id": event.rule_id or "DECEPTION-ENGINE",
                "execution_result": event.execution_result,
                "alert": event.alert,
                "severity": event.severity,
                "edge_node": event.edge_node or "edge-th",
                "body_bytes_sent": event.body_bytes_sent,
                "latency_ms": event.latency_ms,
                "source": event.source,
            }
            self.db.save_log(dynamo_entry)
        except Exception as db_err:
            logger.warning("DynamoDB deception log write error (non-blocking): %s", db_err)


# ClickHouseService.client is one shared object that is not documented as
# thread-safe (see clickhouse_service.save_logs_bulk). Audit logging runs in
# the threadpool via BackgroundTasks, so deception writes are serialised.
_CH_WRITE_LOCK = threading.Lock()


# Global singleton instance
deception_service = DeceptionService()
