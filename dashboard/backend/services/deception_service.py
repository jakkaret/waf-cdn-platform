"""
Dynamic Deception Layer (WAF Honeypot) Service.
Handles attack classification, secure synthetic response generation,
strict anti-caching header enforcement, and fail-safe dual-sink audit logging.
"""

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from services import deception_content
from services.clickhouse_service import ClickHouseService
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
    delay_seconds: float = 0.0  # time-based SQLi: how long the caller holds the response

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
# Synthetic Templates (in memory, per site -- see services/deception_content)
# ---------------------------------------------------------------------------

# What a request without a usable Host header gets; also the fail-safe body.
_DEFAULT_SITE = deception_content.site_for("")
PATH_TRAVERSAL_TEMPLATE: str = deception_content.passwd(_DEFAULT_SITE)
SQLI_TEMPLATE: str = deception_content.schema_dump(_DEFAULT_SITE)

CATEGORIES: Dict[str, str] = {
    "path_traversal": "Path Traversal (LFI)",
    "sql_injection": "SQL Injection (SQLi)",
    "sensitive_file": "Sensitive File Exposure",
    "command_injection": "Command Injection (RCE)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "xss": "Cross-Site Scripting (XSS)",
    "admin_panel": "Admin Panel Probe",
    "honeytoken": "Honeytoken Replay",
}

TEMPLATES_CATALOG: Dict[str, Dict[str, Any]] = {
    "path_traversal": {
        "name": "System file read through traversal (/etc/passwd, shadow, hosts, win.ini, environ)",
        "content_type": "text/plain",
        "description": "Serves the file the payload aims at, generated per site. Unknown targets get /etc/passwd.",
        "body": PATH_TRAVERSAL_TEMPLATE,
    },
    "sql_injection": {
        "name": "Emulated MySQL behind the endpoint",
        "content_type": "application/json",
        "description": "Error-based, UNION (column count and literal reflection), boolean (true/false probes "
                       "differ) and time-based (sleep/benchmark/waitfor delay up to 10 s). JSON for API clients, HTML otherwise.",
        "body": SQLI_TEMPLATE,
    },
    "sensitive_file": {
        "name": "Exposed secrets (.env, wp-config, .git, .aws/credentials, SQL backup, SSH key)",
        "content_type": "text/plain",
        "description": "Plausible config and backup files carrying per-site honeytokens.",
        "body": deception_content.dotenv(_DEFAULT_SITE),
    },
    "command_injection": {
        "name": "Shell command output (id, whoami, uname, cat, ls, env)",
        "content_type": "text/html",
        "description": "Output of the injected command as the www-data user. Network commands stay silent.",
        "body": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
    },
    "ssrf": {
        "name": "Cloud metadata service (169.254.169.254)",
        "content_type": "text/plain",
        "description": "EC2 instance metadata with temporary IAM credentials that are honeytokens.",
        "body": "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\n",
    },
    "xss": {
        "name": "Search page with the payload reflected escaped",
        "content_type": "text/html",
        "description": "Never reflects markup raw, so the honeypot cannot become a real XSS on the customer's domain.",
        "body": "<h2>Search results for &ldquo;&lt;script&gt;&rdquo;</h2>",
    },
    "admin_panel": {
        "name": "Admin / WordPress login that lets anyone in",
        "content_type": "text/html",
        "description": "GET shows a login form; any POST lands on a fake dashboard.",
        "body": "<h2>Administrator login</h2>",
    },
    "honeytoken": {
        "name": "Honeytoken replay",
        "content_type": "text/html",
        "description": "A request carried a secret only the honeypot ever handed out. Logged as critical.",
        "body": "<h2>Dashboard</h2>",
    },
}
for _tid, _t in TEMPLATES_CATALOG.items():
    _t.update(
        id=_tid,
        attack_category=CATEGORIES[_tid],
        status_code=200,
        sample_preview=_t["body"][:80] + ("..." if len(_t["body"]) > 80 else ""),
    )

_HINTS = {
    "path_traversal": "path_traversal", "traversal": "path_traversal", "lfi": "path_traversal",
    "sql_injection": "sql_injection", "sqli": "sql_injection",
    "sensitive_file": "sensitive_file", "command_injection": "command_injection", "rce": "command_injection",
    "ssrf": "ssrf", "xss": "xss", "admin_panel": "admin_panel",
}

# ---------------------------------------------------------------------------
# Deception Service Class
# ---------------------------------------------------------------------------

class DeceptionService:
    """Core deception engine responsible for classification, templating, and fail-safe logging."""

    def __init__(self, ch_service: Optional[ClickHouseService] = None):
        self._ch = ch_service

    @property
    def ch(self) -> ClickHouseService:
        if self._ch is None:
            self._ch = ClickHouseService()
        return self._ch

    @ch.setter
    def ch(self, val: Any):
        self._ch = val

    def classify_attack(
        self,
        uri: str = "/",
        body: str = "",
        template_hint: Optional[str] = None,
        host: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> AttackClassification:
        """
        Attack classification, first match wins:
        0. A honeytoken of this site anywhere in the request.
        1. Explicit rule/header hint.
        2. Signatures over raw and normalized input: traversal, SQLi, SSRF,
           command injection, XSS (ReDoS-safe, inputs bounded at 4 KB).
        3. Probed paths: sensitive files, admin/login panels.
        4. Contextual heuristic fallback (API vs static/resource patterns).
        """
        safe_uri = (uri or "")[:4096]
        safe_body = (body or "")[:4096]

        # Tier 0: honeytoken replay
        if host:
            corpus = safe_uri + " " + safe_body + " " + " ".join(
                str(v)[:1024] for k, v in (headers or {}).items()
                if k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token")
            )
            if deception_content.find_honeytoken(deception_content.site_for(host), corpus):
                return AttackClassification(CATEGORIES["honeytoken"], "honeytoken", 1.0)

        # Tier 1: Explicit hint
        hint = _HINTS.get((template_hint or "").strip().lower())
        if hint:
            return AttackClassification(CATEGORIES[hint], hint, 1.0)

        # Normalized representations
        normalized_uri = payload_normalizer.normalize_string(safe_uri)
        normalized_body = payload_normalizer.normalize_string(safe_body)
        corpus_list = [c for c in (safe_uri, safe_body, normalized_uri, normalized_body) if c]

        # Tier 2: Signature pattern matching
        for regex, tid in (
            (PATH_TRAVERSAL_REGEX, "path_traversal"),
            (SQLI_REGEX, "sql_injection"),
        ):
            if any(regex.search(c) for c in corpus_list):
                return AttackClassification(CATEGORIES[tid], tid, 0.95)
        decoded = normalized_uri + " " + normalized_body
        if deception_content.ssrf_target(decoded):
            return AttackClassification(CATEGORIES["ssrf"], "ssrf", 0.9)
        if deception_content._CMD.search(decoded):
            return AttackClassification(CATEGORIES["command_injection"], "command_injection", 0.9)
        if any(deception_content.XSS_REGEX.search(c) for c in corpus_list):
            return AttackClassification(CATEGORIES["xss"], "xss", 0.9)

        # Tier 3: probed paths
        path = normalized_uri.split("?", 1)[0]
        if deception_content.file_variant(path):
            return AttackClassification(CATEGORIES["sensitive_file"], "sensitive_file", 0.85)
        if deception_content.ADMIN_PATH.search(path):
            return AttackClassification(CATEGORIES["admin_panel"], "admin_panel", 0.8)

        # Tier 4: Contextual heuristic fallback
        uri_lower = safe_uri.lower()
        check_corpus = uri_lower + " " + safe_body.lower()

        # Heuristic SQLi: API/REST routes, database query param keys (form & JSON)
        api_indicators = ["/api/", "/rest/", "/v1/", "/v2/", "/graphql", "/auth", "/login", "/user"]
        query_param_indicators = [
            "q=", "query=", "search=", "id=", "filter=", "user=", "name=", "select=",
            '"q":', '"query":', '"search":', '"id":', '"filter":', '"user":', '"name":', '"select":'
        ]
        if any(ind in check_corpus for ind in api_indicators) or any(ind in check_corpus for ind in query_param_indicators):
            return AttackClassification(CATEGORIES["sql_injection"], "sql_injection", 0.70)

        # Heuristic Path Traversal: file extensions, download paths
        file_ext_indicators = [".php", ".asp", ".aspx", ".jsp", ".txt", ".log", ".conf", ".ini", ".zip", ".tar", ".gz", "/download", "/files/", "/static/"]
        if any(ext in uri_lower for ext in file_ext_indicators):
            return AttackClassification(CATEGORIES["path_traversal"], "path_traversal", 0.70)

        # General default fallback: Path Traversal (believable Unix system file)
        return AttackClassification(CATEGORIES["path_traversal"], "path_traversal", 0.50)

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
        host: str = "",
    ) -> DeceptionResponse:
        """
        Generates a contextual synthetic deception response for this site.
        Guarantees HTTP status 200, strictly synthetic content, and anti-caching
        headers. delay_seconds is set for time-based SQL injection; the caller
        sleeps, so generation itself stays fast.
        """
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        host = host or hdrs.get("x-original-host", "")
        classification = self.classify_attack(
            uri=uri, body=body, template_hint=template_hint or template_id, host=host, headers=headers,
        )
        tid = classification.template_id
        site = deception_content.site_for(host)
        ctx = deception_content.Ctx.build(uri, method, body, hdrs.get("accept", ""))
        delay = 0.0

        if tid == "sql_injection":
            content_type, payload, extra = deception_content.render_sql(site, ctx)
            delay = deception_content.sql_delay(ctx.text)
        elif tid in ("path_traversal", "sensitive_file"):
            variant = deception_content.file_variant(ctx.uri) or deception_content.file_variant(ctx.text) or "passwd"
            content_type, payload, extra = deception_content.render_file(site, variant, ctx)
        elif tid == "command_injection":
            content_type, payload, extra = deception_content.render_command(site, ctx)
        elif tid == "ssrf":
            content_type, payload, extra = deception_content.render_ssrf(site, ctx)
        elif tid == "xss":
            content_type, payload, extra = deception_content.render_xss(site, ctx)
        else:  # admin_panel, honeytoken
            content_type, payload, extra = deception_content.render_admin(site, ctx, logged_in=tid == "honeytoken")

        response_headers = dict(SECURE_DECEPTION_HEADERS)
        response_headers.update(extra)
        if request_id:
            response_headers["X-Request-ID"] = request_id

        return DeceptionResponse(
            status_code=200,
            content_type=content_type,
            body=payload,
            headers=response_headers,
            template_id=tid,
            category=classification.category,
            delay_seconds=delay,
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


# ClickHouseService.client is one shared object that is not documented as
# thread-safe (see clickhouse_service.save_logs_bulk). Audit logging runs in
# the threadpool via BackgroundTasks, so deception writes are serialised.
_CH_WRITE_LOCK = threading.Lock()


# Global singleton instance
deception_service = DeceptionService()
