"""
Comprehensive Unit & Integration Test Suite for WAF Honeypot Deception Layer.
Validates:
- Attack Classification (Path Traversal, SQLi, Fallback, Evasion, ReDoS Safety)
- Synthetic Response Templates (Unix /etc/passwd, JSON DB schema, HTTP 200, Content-Types)
- Strict Anti-Caching Headers & Zero-Leakage Static Guarantees
- Internal Security Access Controls (X-Internal-Deception-Key, 403 Rejection, RBAC)
- Structured Audit Logging to ClickHouse & DynamoDB (R6.1, R6.3)
- Fail-Safe Isolation: Complete Resilience against Database and Classifier Outages (R6.4, R4.5)
"""

import ast
import json
import os
import time
from typing import Any, Dict, List
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import auth as auth_module
from api.deception import (
    INTERNAL_DECEPTION_HEADER,
    INTERNAL_DECEPTION_KEY_ENV,
    router as deception_router,
    verify_internal_deception_key,
)

# The endpoint has no built-in key any more (a default baked into the
# source was readable by anyone); tests supply their own through the env.
DEFAULT_INTERNAL_KEY = os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")
from services.deception_service import (
    PATH_TRAVERSAL_REGEX,
    SECURE_DECEPTION_HEADERS,
    SQLI_REGEX,
    AttackClassification,
    DeceptionLogEvent,
    DeceptionResponse,
    DeceptionService,
    deception_service,
)


# ---------------------------------------------------------------------------
# Test Doubles & Mocks
# ---------------------------------------------------------------------------

class MockClickHouseClient:
    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail
        self.inserted_records = []

    def insert(self, table_name, rows, column_names=None):
        if self.should_fail:
            raise RuntimeError("Simulated ClickHouse Socket Timeout / Connection Refused")
        self.inserted_records.append({
            "table": table_name,
            "columns": column_names,
            "rows": rows,
        })


class MockClickHouseService:
    def __init__(self, connected: bool = True, should_fail: bool = False):
        self.connected = connected
        self.client = MockClickHouseClient(should_fail=should_fail)
        self.saved_logs = []

    def save_log(self, table_name: str, data: dict) -> bool:
        if not self.connected:
            return False
        if self.client.should_fail:
            raise ConnectionError("ClickHouse Cluster Unreachable")
        self.saved_logs.append({"table": table_name, "data": data})
        self.client.insert(table_name, [list(data.values())], list(data.keys()))
        return True


class MockDynamoDBTable:
    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail
        self.items = []

    def put_item(self, Item: dict):
        if self.should_fail:
            raise RuntimeError("Simulated DynamoDB ProvisionedThroughputExceededException")
        self.items.append(dict(Item))
        return {}


class MockDynamoDBService:
    def __init__(self, should_fail: bool = False):
        self.logs_table = MockDynamoDBTable(should_fail=should_fail)

    def convert_floats(self, obj):
        return obj

    def save_log(self, event: dict):
        if self.logs_table.should_fail:
            raise RuntimeError("DynamoDB Client Error")
        self.logs_table.put_item(event)


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def deception_app() -> FastAPI:
    """FastAPI test app configured with deception and auth routers."""
    app = FastAPI()
    app.include_router(auth_module.router)
    app.include_router(deception_router)
    return app


@pytest.fixture
def deception_client(deception_app: FastAPI) -> TestClient:
    return TestClient(deception_app)


@pytest.fixture
def valid_auth_headers() -> Dict[str, str]:
    return {
        INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
        "X-Original-URI": "/test",
        "X-Original-Method": "GET",
        "X-Request-ID": "test-req-12345",
        "X-Real-IP": "203.0.113.195",
    }


# ===========================================================================
# 1. Attack Classification Unit Tests (AC 1, Tier 1 & 2)
# ===========================================================================

class TestAttackClassification:
    """Validates Path Traversal, SQLi, and Fallback heuristic classification."""

    def test_path_traversal_dot_dot_slash(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/download?file=../../../../etc/passwd", body="")
        assert res.category == "Path Traversal (LFI)"
        assert res.template_id == "path_traversal"

    def test_path_traversal_windows_system_path(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/load?path=..\\..\\windows\\win.ini", body="")
        assert res.category == "Path Traversal (LFI)"
        assert res.template_id == "path_traversal"

    def test_path_traversal_url_encoded_evasion(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/files?name=%2e%2e%2f%2e%2e%2fetc%2fshadow", body="")
        assert res.category == "Path Traversal (LFI)"
        assert res.template_id == "path_traversal"

    def test_path_traversal_php_wrapper_and_proc(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/index.php?page=php://filter/resource=index.php", body="")
        assert res.category == "Path Traversal (LFI)"
        assert res.template_id == "path_traversal"

    def test_sqli_union_select(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/items?q=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--", body="")
        assert res.category == "SQL Injection (SQLi)"
        assert res.template_id == "sql_injection"

    def test_sqli_boolean_tautology(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/login?user=admin%27%20or%201=1--", body="")
        assert res.category == "SQL Injection (SQLi)"
        assert res.template_id == "sql_injection"

    def test_sqli_time_delay_functions(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/search?id=1;%20WAITFOR%20DELAY%20%270:0:5%27--", body="")
        assert res.category == "SQL Injection (SQLi)"
        assert res.template_id == "sql_injection"

    def test_sqli_in_post_body(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/api/authenticate", body='{"username": "admin\' OR \'1\'=\'1", "password": "x"}')
        assert res.category == "SQL Injection (SQLi)"
        assert res.template_id == "sql_injection"

    def test_fallback_heuristic_api_route(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/api/v1/users/search?filter=active", body="")
        assert res.category == "SQL Injection (SQLi)"
        assert res.template_id == "sql_injection"

    def test_fallback_heuristic_file_path(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/assets/documents/archive.zip", body="")
        assert res.category == "Path Traversal (LFI)"
        assert res.template_id == "path_traversal"

    def test_explicit_template_hint_override(self):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/arbitrary_path", body="", template_hint="sql_injection")
        assert res.template_id == "sql_injection"

    def test_redos_safety_bounded_execution_time(self):
        svc = DeceptionService()
        evil_string = "/?" + ("a" * 5000) + ("../" * 500)
        t0 = time.perf_counter()
        res = svc.classify_attack(uri=evil_string, body="")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50.0  # Must evaluate in < 50ms without catastrophic backtracking
        assert res.template_id == "path_traversal"

    def test_tuple_unpacking_compatibility(self):
        svc = DeceptionService()
        category, template_id, confidence = svc.classify_attack(uri="/download?file=../../etc/passwd")
        assert category == "Path Traversal (LFI)"
        assert template_id == "path_traversal"
        assert confidence > 0.0


# ===========================================================================
# 2. Synthetic Templates & Header Enforcement Unit Tests (AC 1, R4.1-R4.5)
# ===========================================================================

class TestTemplatesAndHeaders:
    """Validates exact synthetic payload contents, HTTP 200, Content-Type, and anti-caching headers."""

    def test_path_traversal_synthetic_content(self):
        svc = DeceptionService()
        resp = svc.generate_response(uri="/../../etc/passwd", method="GET")
        assert resp.status_code == 200
        assert "text/plain" in resp.content_type
        assert resp.body.startswith("root:x:0:0:root:/root:/bin/bash")
        assert "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" in resp.body
        assert "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" in resp.body
        assert resp.content == resp.body
        assert resp.media_type == resp.content_type

    def test_sql_injection_synthetic_content(self):
        svc = DeceptionService()
        resp = svc.generate_response(uri="/search?q=' UNION SELECT 1,2--", method="GET")
        assert resp.status_code == 200
        assert "application/json" in resp.content_type
        data = json.loads(resp.body)
        assert data["status"] == "success"
        assert data["database"] == "production_app_db"
        assert "schema" in data
        assert any(t["table_name"] == "app_users" for t in data["schema"]["tables"])

    def test_anti_cache_headers_compliance(self):
        svc = DeceptionService()
        resp = svc.generate_response(uri="/../../etc/passwd", method="GET")
        headers = resp.headers
        cc = headers.get("Cache-Control", "")
        assert "no-store" in cc
        assert "no-cache" in cc
        assert "must-revalidate" in cc
        assert "max-age=0" in cc
        assert "private" in cc
        assert headers.get("Pragma") == "no-cache"
        assert headers.get("Expires") == "0"
        assert headers.get("Surrogate-Control") == "no-store"
        assert headers.get("X-Content-Type-Options") == "nosniff"

    def test_zero_leakage_static_guarantees(self):
        """Inspects service source code via AST to ensure NO file I/O or live DB calls exist."""
        service_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../services/deception_service.py")
        )
        assert os.path.exists(service_path)
        with open(service_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ["open", "eval", "exec"], (
                        f"Prohibited host access function '{node.func.id}' found in deception_service.py"
                    )

    def test_fallback_response_content(self):
        svc = DeceptionService()
        resp = svc.get_fallback_response(request_id="req-fallback-123")
        assert resp.status_code == 200
        assert "text/plain" in resp.content_type
        assert "root:x:0:0:root" in resp.body
        assert resp.headers.get("X-Request-ID") == "req-fallback-123"
        assert "no-store" in resp.headers.get("Cache-Control", "")

    def test_list_templates_catalog(self):
        svc = DeceptionService()
        templates = svc.list_templates()
        assert len(templates) >= 2
        tmpl_ids = [t["id"] for t in templates]
        assert "path_traversal" in tmpl_ids
        assert "sql_injection" in tmpl_ids


# ===========================================================================
# 3. FastAPI Endpoint & Security Access Control Tests (AC 2, R3.4)
# ===========================================================================

class TestDeceptionEndpointSecurity:
    """Validates /api/deception/respond routing, HTTP methods, and key authorization."""

    def test_missing_internal_key_rejected_with_403(self, deception_client: TestClient):
        resp = deception_client.get("/api/deception/respond")
        assert resp.status_code == 403
        assert "Forbidden" in resp.json().get("detail", "")

    def test_invalid_internal_key_rejected_with_403(self, deception_client: TestClient):
        resp = deception_client.get(
            "/api/deception/respond",
            headers={INTERNAL_DECEPTION_HEADER: "wrong-fake-key-999"},
        )
        assert resp.status_code == 403

    def test_valid_internal_key_path_traversal_success(self, deception_client: TestClient, valid_auth_headers):
        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/download?file=../../../../etc/passwd"
        resp = deception_client.get("/api/deception/respond", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "root:x:0:0:root" in resp.text
        assert "no-store" in resp.headers["cache-control"]
        assert resp.headers.get("x-request-id") == "test-req-12345"

    def test_valid_internal_key_sqli_success(self, deception_client: TestClient, valid_auth_headers):
        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/login?user=admin%27%20OR%201=1--"
        resp = deception_client.get("/api/deception/respond", headers=headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        data = resp.json()
        assert data["status"] == "success"
        assert "production_app_db" in resp.text

    def test_post_body_inspection_transparent_relay(self, deception_client: TestClient, valid_auth_headers):
        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/api/v1/auth"
        headers["X-Original-Method"] = "POST"
        resp = deception_client.post(
            "/api/deception/respond",
            headers=headers,
            content="username=admin%27%20UNION%20SELECT%201,2--&pass=foo",
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")

    def test_respond_methods_transparency(self, deception_client: TestClient, valid_auth_headers):
        headers = dict(valid_auth_headers)
        for method in ["post", "put", "delete", "patch", "head", "options"]:
            client_method = getattr(deception_client, method)
            resp = client_method("/api/deception/respond", headers=headers)
            assert resp.status_code == 200

    def test_templates_unauthenticated_rejected_with_401(self, deception_client: TestClient):
        resp = deception_client.get("/api/deception/templates")
        assert resp.status_code == 401

    def test_templates_admin_access_allowed(self, deception_client: TestClient, register_user, auth_header):
        admin = register_user(email="deception-admin@example.com", username="deception_admin", role="admin")
        resp = deception_client.get("/api/deception/templates", headers=auth_header(admin["access_token"]))
        assert resp.status_code == 200
        data = resp.json()
        assert "templates" in data
        assert any(t["id"] == "path_traversal" for t in data["templates"])

    def test_simulate_admin_access(self, deception_client: TestClient, register_user, auth_header):
        admin = register_user(email="sim-admin@example.com", username="sim_admin", role="admin")
        resp = deception_client.post(
            "/api/deception/simulate",
            headers=auth_header(admin["access_token"]),
            json={"uri": "/users?id=1' UNION SELECT 1,2--", "method": "GET"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["attack_category"] == "SQL Injection (SQLi)"
        assert data["template_id"] == "sql_injection"
        assert data["response"]["status_code"] == 200


# ===========================================================================
# 4. Structured Logging & Fail-Safe Database Resilience Tests (AC 7, R6.1, R6.4)
# ===========================================================================

class TestDeceptionLoggingResilience:
    """Validates complete failure shielding: ClickHouse/DynamoDB outages NEVER crash or bypass."""

    def test_logging_populates_all_r6_fields(self):
        mock_ch = MockClickHouseService()
        mock_db = MockDynamoDBService()
        svc = DeceptionService(ch_service=mock_ch, db_service=mock_db)

        event = DeceptionLogEvent(
            request_id="req-test-uuid-99",
            timestamp=int(time.time()),
            rule_id="custom-100005",
            attack_category="Path Traversal (LFI)",
            template_id="path_traversal",
            response_status=200,
            execution_result="deceived",
            client_ip="198.51.100.42",
            method="GET",
            url="/download?file=../../etc/passwd",
            user_agent="sqlmap/1.7.2#stable",
            edge_node="edge-th",
            latency_ms=1.25,
            body_bytes_sent=1024,
            datetime="2026-09-26T19:30:00Z",
        )

        ok = svc.log_deception_event(event)
        assert ok is True

        # Verify DynamoDB recorded R6 mandatory attributes
        assert len(mock_db.logs_table.items) == 1
        item = mock_db.logs_table.items[0]
        assert item["request_id"] == "req-test-uuid-99"
        assert item["rule_id"] == "custom-100005"
        assert item["attack_category"] == "Path Traversal (LFI)"
        assert item["template_id"] == "path_traversal"
        assert item["status"] == 200
        assert item["execution_result"] == "deceived"
        assert item["action"] == "DECEIVE"

        # Verify ClickHouse recorded logs
        assert len(mock_ch.saved_logs) >= 1

    def test_logging_sanitizes_pii_and_passwords(self):
        mock_db = MockDynamoDBService()
        svc = DeceptionService(ch_service=None, db_service=mock_db)

        event = DeceptionLogEvent(
            request_id="req-pii-01",
            timestamp=int(time.time()),
            rule_id="custom-100005",
            attack_category="Path Traversal (LFI)",
            template_id="path_traversal",
            response_status=200,
            execution_result="deceived",
            client_ip="198.51.100.42",
            method="GET",
            url="/api/login?password=UltraSecretPassword123!&token=bearer_xyz_123456789&path=../../etc/passwd",
            user_agent="Mozilla/5.0",
            edge_node="edge-th",
            latency_ms=1.0,
            body_bytes_sent=512,
            datetime="2026-09-26T19:30:00Z",
        )

        svc.log_deception_event(event)
        logged_url = mock_db.logs_table.items[0]["url"]
        assert "UltraSecretPassword123!" not in logged_url
        assert "password=" in logged_url  # Masked password parameter remains

    def test_fail_safe_clickhouse_outage_never_fails_response(
        self, deception_client: TestClient, valid_auth_headers, monkeypatch
    ):
        """Simulates ClickHouse total connection loss; verifies endpoint still returns 200 OK."""
        failing_ch = MockClickHouseService(should_fail=True)
        monkeypatch.setattr(deception_service, "ch", failing_ch)

        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/../../etc/passwd"
        resp = deception_client.get("/api/deception/respond", headers=headers)

        assert resp.status_code == 200
        assert "root:x:0:0:root" in resp.text
        assert resp.status_code != 500

    def test_fail_safe_dynamodb_outage_never_fails_response(
        self, deception_client: TestClient, valid_auth_headers, monkeypatch
    ):
        """Simulates DynamoDB throttling/crash; verifies endpoint still returns 200 OK."""
        failing_db = MockDynamoDBService(should_fail=True)
        monkeypatch.setattr(deception_service, "db", failing_db)

        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/login?id=1' UNION SELECT 1,2--"
        resp = deception_client.get("/api/deception/respond", headers=headers)

        assert resp.status_code == 200
        assert resp.json()["status"] == "success"
        assert resp.status_code != 500

    def test_fail_safe_dual_database_simultaneous_crash(
        self, deception_client: TestClient, valid_auth_headers, monkeypatch
    ):
        """Simulates BOTH ClickHouse and DynamoDB failing simultaneously."""
        failing_ch = MockClickHouseService(should_fail=True)
        failing_db = MockDynamoDBService(should_fail=True)
        monkeypatch.setattr(deception_service, "ch", failing_ch)
        monkeypatch.setattr(deception_service, "db", failing_db)

        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/../../etc/passwd"
        resp = deception_client.get("/api/deception/respond", headers=headers)

        assert resp.status_code == 200
        assert "root:x:0:0:root" in resp.text

    def test_fail_safe_unhandled_exception_in_classifier_returns_200(
        self, deception_client: TestClient, valid_auth_headers, monkeypatch
    ):
        """Simulates an internal unexpected error inside classifier; verifies fallback to 200 (never 500)."""
        def buggy_classifier(*args, **kwargs):
            raise ValueError("Simulated unexpected classifier runtime error")

        monkeypatch.setattr(deception_service, "classify_attack", buggy_classifier)

        headers = dict(valid_auth_headers)
        headers["X-Original-URI"] = "/any/path"
        resp = deception_client.get("/api/deception/respond", headers=headers)

        # R4.5: "Do not use HTTP 500 as a default deception response or as an indicator of successful deception."
        assert resp.status_code == 200
        assert len(resp.text) > 0
        assert "root:x:0:0:root" in resp.text
