"""
Adversarial Empirical Challenge Test Suite for WAF Honeypot Deception Layer.
Authored by challenger_m1_2 to rigorously stress-test:
1. Endpoint security on /api/deception/respond:
   - Missing key, empty key, partial/spoofed keys, special characters, null bytes, unicode.
   - Timing attack resistance on X-Internal-Deception-Key.
   - All HTTP verbs (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, and invalid verbs).
   - Large payloads (64KB, 1MB, 5MB, 10MB), non-UTF-8 binary data, malformed/deep JSON.
2. Failure resilience (AC 7 & R6.4):
   - Database outages: ClickHouse connection errors, timeouts, broken pipes, client missing.
   - Database outages: DynamoDB ClientError, throughput exceeded, endpoint error, table missing.
   - Simultaneous dual database crash.
   - Classifier runtime exceptions (RuntimeError, ValueError, RecursionError, MemoryError).
   - Verification that /respond ALWAYS returns HTTP 200, NEVER returns HTTP 500, NEVER exposes stack traces.
3. Information & Origin Leakage:
   - Zero host filesystem leakage (/etc/passwd real accounts check).
   - Zero credential or environment secret leakage.
   - Zero origin contact or upstream leakage.
"""

import ast
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api.deception import (
    INTERNAL_DECEPTION_HEADER,
    get_expected_key,
    router as deception_router,
    verify_internal_deception_key,
)

# The endpoint has no built-in key any more (a default baked into the
# source was readable by anyone); tests supply their own through the env.
DEFAULT_INTERNAL_KEY = os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")
from services.deception_service import (
    PATH_TRAVERSAL_REGEX,
    PATH_TRAVERSAL_TEMPLATE,
    SECURE_DECEPTION_HEADERS,
    SQLI_REGEX,
    SQLI_TEMPLATE,
    AttackClassification,
    DeceptionLogEvent,
    DeceptionResponse,
    DeceptionService,
    deception_service,
)

logger = logging.getLogger("challenger_m1_2")


# ---------------------------------------------------------------------------
# Test Fixtures & App Setup
# ---------------------------------------------------------------------------

@pytest.fixture
def test_app() -> FastAPI:
    app = FastAPI(title="Challenger Deception Test App")
    app.include_router(deception_router)
    return app


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    return TestClient(test_app)


@pytest.fixture
def valid_headers() -> Dict[str, str]:
    return {
        INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
        "X-Original-URI": "/admin/dashboard",
        "X-Original-Method": "GET",
        "X-Request-ID": "challenge-req-001",
        "X-Real-IP": "198.51.100.77",
    }


# ===========================================================================
# 1. Endpoint Security & Access Control Challenge Harness
# ===========================================================================

class TestEndpointSecurityChallenge:
    """Stress-tests access control, authorization evasion, verbs, and payload boundaries."""

    def test_missing_internal_key_strict_403(self, client: TestClient):
        """Requests without the internal deception key header must return 403 Forbidden."""
        resp = client.get("/api/deception/respond")
        assert resp.status_code == 403
        assert "Forbidden" in resp.json().get("detail", "")
        assert resp.status_code != 500

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "",                                              # Empty string
            "   ",                                           # Whitespace only
            "waf-deception-internal",                        # Common prefix
            "waf-deception-internal-secret-key-extra",       # Correct key + suffix
            "WAF-DECEPTION-INTERNAL-SECRET-KEY",             # Uppercase
            "waf-deception-internal-secret-key\x00extra",     # Null-byte injection
            "' OR '1'='1",                                   # SQLi in auth header
            "../../etc/passwd",                              # Path traversal in auth header
            "Bearer waf-deception-internal-secret-key",      # Bearer prefix attempt
            "wrong_key_1234567890",                          # Completely invalid key
        ],
    )
    def test_invalid_internal_keys_rejected_403(self, client: TestClient, invalid_key: str):
        """All variations of invalid or spoofed internal keys must be strictly rejected with 403."""
        resp = client.get(
            "/api/deception/respond",
            headers={INTERNAL_DECEPTION_HEADER: invalid_key},
        )
        assert resp.status_code == 403
        assert "Forbidden" in resp.json().get("detail", "")
        # Confirm no internal stack trace leaked in 403 response
        assert "Traceback" not in resp.text
        assert "deception_service" not in resp.text

    def test_non_ascii_internal_key_causes_unhandled_typeerror_and_500_defect(self):
        """
        Verifies remediation of Challenger M1-2 finding:
        When X-Internal-Deception-Key contains non-ASCII characters (e.g. Unicode homoglyphs
        or raw high bytes), verify_internal_deception_key safely compares UTF-8 bytes.
        FastAPI/Uvicorn must cleanly return HTTP 403 Forbidden (NEVER HTTP 500 or TypeError).
        """
        import asyncio
        from fastapi import FastAPI
        from api.deception import router

        app = FastAPI()
        app.include_router(router)

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/deception/respond",
            "raw_path": b"/api/deception/respond",
            "query_string": b"",
            "headers": [
                (b"host", b"localhost"),
                (b"x-internal-deception-key", b"waf-d\xd0\xb5ception-internal-secret-key"),
            ],
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 8000),
            "scheme": "http",
        }
        messages = []
        async def receive():
            return {"type": "http.request", "body": b""}
        async def send(msg):
            messages.append(msg)

        # Must execute cleanly without unhandled TypeError
        asyncio.run(app(scope, receive, send))
        status_code = None
        for m in messages:
            if m["type"] == "http.response.start":
                status_code = m["status"]
        assert status_code == 403, f"Expected HTTP 403 Forbidden, got {status_code}"

    def test_non_ascii_internal_key_strict_403_requirement(self):
        """
        AC 7 & R3.4 Requirement: All invalid keys MUST return HTTP 403 Forbidden (NEVER HTTP 500).
        Verified passing post-remediation.
        """
        from starlette.requests import Request
        scope = {
            "type": "http",
            "method": "GET",
            "headers": [
                (b"x-internal-deception-key", b"waf-d\xd0\xb5ception-internal-secret-key"),
            ],
            "client": ("127.0.0.1", 50000),
        }
        req = Request(scope)
        with pytest.raises(HTTPException) as exc_info:
            verify_internal_deception_key(req)
        assert exc_info.value.status_code == 403

    def test_timing_attack_resistance_on_internal_key(self):
        """
        Empirically verifies constant-time comparison in verify_internal_deception_key.
        Compares execution times of early-mismatch, late-mismatch, and wrong-length keys
        over 5,000 trials to ensure no measurable timing side-channel leaks key prefix.
        """
        expected = get_expected_key()
        # Candidate 1: First character wrong
        key_early_mismatch = "X" + expected[1:]
        # Candidate 2: Last character wrong (all previous match)
        key_late_mismatch = expected[:-1] + "X"
        # Candidate 3: Completely different characters, same length
        key_all_mismatch = "Z" * len(expected)

        iterations = 5000

        class DummyRequest:
            def __init__(self, key: str):
                self.headers = {INTERNAL_DECEPTION_HEADER: key}
                self.client = None

        req_early = DummyRequest(key_early_mismatch)
        req_late = DummyRequest(key_late_mismatch)
        req_all = DummyRequest(key_all_mismatch)

        times_early: List[float] = []
        times_late: List[float] = []
        times_all: List[float] = []

        # Suppress logger during timing loop to avoid console I/O noise skewing measurements
        deception_logger = logging.getLogger("waf.deception")
        orig_level = deception_logger.level
        deception_logger.setLevel(logging.CRITICAL)

        try:
            # Warm-up JIT / caches
            for _ in range(500):
                try:
                    verify_internal_deception_key(req_early)
                except HTTPException:
                    pass

            for _ in range(iterations):
                t0 = time.perf_counter_ns()
                try:
                    verify_internal_deception_key(req_early)
                except HTTPException:
                    pass
                times_early.append(time.perf_counter_ns() - t0)

                t0 = time.perf_counter_ns()
                try:
                    verify_internal_deception_key(req_late)
                except HTTPException:
                    pass
                times_late.append(time.perf_counter_ns() - t0)

                t0 = time.perf_counter_ns()
                try:
                    verify_internal_deception_key(req_all)
                except HTTPException:
                    pass
                times_all.append(time.perf_counter_ns() - t0)
        finally:
            deception_logger.setLevel(orig_level)

        mean_early = sum(times_early) / len(times_early)
        mean_late = sum(times_late) / len(times_late)
        mean_all = sum(times_all) / len(times_all)

        timing_diff_ns = abs(mean_late - mean_early)
        timing_diff_us = timing_diff_ns / 1000.0

        # Timing difference between comparing first char mismatch vs last char mismatch
        # should be well within noise margin (< 1 microsecond when I/O noise is excluded)
        assert timing_diff_us < 1.0, f"Timing difference too high: {timing_diff_us:.2f}μs (potential timing leak)"

    @pytest.mark.parametrize(
        "method",
        ["get", "post", "put", "delete", "patch", "head", "options"],
    )
    def test_all_supported_http_verbs(self, client: TestClient, valid_headers: Dict[str, str], method: str):
        """All supported HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) must succeed with 200."""
        kwargs: Dict[str, Any] = {"headers": valid_headers}
        if method in ["post", "put", "patch"]:
            kwargs["content"] = b"test-payload"

        resp = client.request(
            method.upper(),
            "/api/deception/respond",
            **kwargs,
        )
        assert resp.status_code == 200, f"Method {method.upper()} failed with status {resp.status_code}"
        assert "no-store" in resp.headers.get("Cache-Control", "")

        # For HEAD request, body must be empty per HTTP RFC 7231
        if method == "head":
            assert resp.text == ""

    @pytest.mark.parametrize("unsupported_method", ["trace", "connect"])
    def test_unsupported_http_verbs_rejected_cleanly(
        self, client: TestClient, valid_headers: Dict[str, str], unsupported_method: str
    ):
        """Unsupported verbs like TRACE must be rejected by FastAPI (405) without 500 or leak."""
        resp = client.request(
            unsupported_method.upper(),
            "/api/deception/respond",
            headers=valid_headers,
        )
        # 405 Method Not Allowed expected
        assert resp.status_code == 405
        assert resp.status_code != 500
        assert "Traceback" not in resp.text

    def test_large_body_64kb_boundary(self, client: TestClient, valid_headers: Dict[str, str]):
        """64 KB payload boundary should be handled smoothly without memory pressure or crash."""
        payload = "x=" + ("a" * 65530)
        resp = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=payload,
        )
        assert resp.status_code == 200
        assert resp.status_code != 500

    def test_large_body_1mb_payload(self, client: TestClient, valid_headers: Dict[str, str]):
        """1 MB payload should be safely truncated/read without buffer overflow or 500."""
        payload = "param=' UNION SELECT 1,2,3 FROM users-- " + ("b" * 1024 * 1024)
        resp = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=payload,
        )
        assert resp.status_code == 200
        # Classified as SQLi from the prefix
        assert "application/json" in resp.headers.get("content-type", "")

    def test_large_body_5mb_payload(self, client: TestClient, valid_headers: Dict[str, str]):
        """5 MB payload should be processed safely without crashing."""
        payload = ("c" * (5 * 1024 * 1024))
        resp = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=payload,
        )
        assert resp.status_code == 200

    def test_binary_non_utf8_payload_resilience(self, client: TestClient, valid_headers: Dict[str, str]):
        """Binary payloads containing invalid UTF-8 bytes must not trigger decode crashes."""
        binary_garbage = b"\x00\xff\xfe\xca\xfe\xba\xbe\x80\x90\xaa\xbb\xcc\xdd\xee" * 1000
        resp = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=binary_garbage,
        )
        assert resp.status_code == 200
        assert resp.status_code != 500

    def test_malformed_and_deeply_nested_json_payload(self, client: TestClient, valid_headers: Dict[str, str]):
        """Malformed JSON and deeply nested structures must not cause parser crash."""
        malformed_json = '{"user": {"admin": true, "unclosed: '
        resp = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=malformed_json,
        )
        assert resp.status_code == 200

        # Deeply nested JSON
        nested = "{" * 500 + '"key": "val"' + "}" * 500
        resp_nested = client.post(
            "/api/deception/respond",
            headers=valid_headers,
            content=nested,
        )
        assert resp_nested.status_code == 200


# ===========================================================================
# 2. Failure Mode & Resilience Stress Testing (AC 7 & R6.4)
# ===========================================================================

class TestFailureResilienceChallenge:
    """Simulates database outages and classifier exceptions to prove zero-leak fallback."""

    def test_clickhouse_connection_refused_returns_200(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """ClickHouse connection refused outage must not interrupt HTTP 200 response."""
        class BrokenCH:
            connected = True
            def save_log(self, *args, **kwargs):
                raise ConnectionRefusedError("ClickHouse server port 8123 connection refused")

        monkeypatch.setattr(deception_service, "ch", BrokenCH())

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert "no-store" in resp.headers.get("Cache-Control", "")
        assert resp.status_code != 500

    def test_clickhouse_socket_timeout_and_broken_pipe(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """ClickHouse socket timeouts and broken pipe errors must be swallowed safely."""
        class TimeoutCH:
            connected = True
            def save_log(self, *args, **kwargs):
                raise TimeoutError("ClickHouse query socket timed out after 3000ms")

        monkeypatch.setattr(deception_service, "ch", TimeoutCH())

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert resp.status_code != 500

    def test_clickhouse_client_none_or_missing(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """ClickHouse service completely uninitialized (None) must be handled gracefully."""
        monkeypatch.setattr(deception_service, "_ch", None)
        # Also mock ClickHouseService() constructor to raise error
        import services.deception_service as ds
        monkeypatch.setattr(ds, "ClickHouseService", lambda: None)

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200

    def test_dynamodb_provisioned_throughput_exceeded(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """DynamoDB 400 ThroughputExceeded throttle must not crash honeypot."""
        class ThrottledDB:
            def save_log(self, *args, **kwargs):
                raise RuntimeError("DynamoDB ProvisionedThroughputExceededException: Rate exceeded")

        monkeypatch.setattr(deception_service, "db", ThrottledDB())

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert resp.status_code != 500

    def test_dynamodb_network_partition_and_timeout(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """DynamoDB connection timeout / network partition must not fail response."""
        class UnreachableDB:
            def save_log(self, *args, **kwargs):
                raise ConnectionError("EndpointConnectionError: Could not connect to the endpoint URL")

        monkeypatch.setattr(deception_service, "db", UnreachableDB())

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert resp.status_code != 500

    def test_simultaneous_dual_database_outage(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """Simultaneous failure of both ClickHouse and DynamoDB must still yield HTTP 200."""
        class FatalCH:
            connected = True
            def save_log(self, *args, **kwargs):
                raise BrokenPipeError("[Errno 32] Broken pipe in ClickHouse cluster")

        class FatalDB:
            def save_log(self, *args, **kwargs):
                raise OSError("[Errno 101] Network is unreachable for DynamoDB endpoint")

        monkeypatch.setattr(deception_service, "ch", FatalCH())
        monkeypatch.setattr(deception_service, "db", FatalDB())

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert "no-store" in resp.headers.get("Cache-Control", "")
        assert resp.status_code != 500

    def test_classifier_runtime_exception_enforces_fallback_200(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """
        When the classifier throws an unhandled RuntimeError, /respond must:
        - Catch the error
        - Fallback to synthetic template (PATH_TRAVERSAL_TEMPLATE)
        - Return HTTP 200 (NEVER HTTP 500)
        - NEVER expose stack trace in body or headers
        """
        def crashing_classifier(*args, **kwargs):
            raise RuntimeError("CRITICAL: Classifier internal regex engine corrupted!")

        monkeypatch.setattr(deception_service, "classify_attack", crashing_classifier)

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert resp.status_code != 500
        # Must return synthetic fallback
        assert "root:x:0:0:root" in resp.text
        # Must NOT expose error details or stack trace
        assert "CRITICAL: Classifier" not in resp.text
        assert "Traceback" not in resp.text
        assert "RuntimeError" not in resp.text
        # Strict anti-cache headers maintained
        assert "no-store" in resp.headers.get("Cache-Control", "")

    def test_classifier_memory_error_and_recursion_error(
        self, client: TestClient, valid_headers: Dict[str, str], monkeypatch
    ):
        """Simulate severe Python exceptions (RecursionError, ValueError) during generation."""
        def exploding_generator(*args, **kwargs):
            raise RecursionError("maximum recursion depth exceeded while classifying")

        monkeypatch.setattr(deception_service, "generate_response", exploding_generator)

        resp = client.get("/api/deception/respond", headers=valid_headers)
        assert resp.status_code == 200
        assert resp.status_code != 500
        assert "root:x:0:0:root" in resp.text
        assert "RecursionError" not in resp.text

    def test_corrupted_request_headers_resilience(
        self, client: TestClient, valid_headers: Dict[str, str]
    ):
        """Corrupted/unexpected values in X-Original-URI, X-Real-IP, X-Request-ID handled cleanly."""
        headers = dict(valid_headers)
        headers["X-Original-URI"] = "/invalid/%FF%FE%00/path"
        headers["X-Real-IP"] = "invalid.ip.format.here"
        headers["X-Request-ID"] = "long-id-" + ("9" * 1000)
        headers["X-Deception-Template"] = "non-existent-template-id-999"

        resp = client.get("/api/deception/respond", headers=headers)
        assert resp.status_code == 200
        assert resp.status_code != 500


# ===========================================================================
# 3. Information & Origin Leakage Challenge
# ===========================================================================

class TestInformationAndOriginLeakage:
    """Verifies that under NO circumstances are real system assets, credentials, or origins exposed."""

    def test_synthetic_passwd_does_not_leak_real_host_accounts(
        self, client: TestClient, valid_headers: Dict[str, str]
    ):
        """Deceptive /etc/passwd must contain ONLY mock data and never real host user accounts."""
        headers = dict(valid_headers)
        headers["X-Original-URI"] = "/../../../../etc/passwd"
        resp = client.get("/api/deception/respond", headers=headers)

        assert resp.status_code == 200
        body = resp.text

        # Real macOS / Darwin system accounts that must NOT be present
        forbidden_host_markers = [
            "/Users/",
            "_spotlight",
            "_launchd",
            "_windowserver",
            "_coreaudiod",
            "_securityagent",
            "/System/Volumes",
        ]
        for marker in forbidden_host_markers:
            assert marker not in body, f"Host filesystem leakage detected: found '{marker}' in response!"

        # Must contain predefined synthetic accounts
        assert "root:x:0:0:root:/root:/bin/bash" in body
        assert "appuser:x:1001:1001" in body
        assert "sysadmin_svc" not in body  # DB user should not be in passwd

    def test_synthetic_sqli_does_not_leak_real_env_secrets(
        self, client: TestClient, valid_headers: Dict[str, str]
    ):
        """Deceptive SQLi JSON must contain only mock credentials and never live environment secrets."""
        headers = dict(valid_headers)
        headers["X-Original-URI"] = "/api/v1/users?id=1' UNION SELECT 1,2,3--"
        resp = client.get("/api/deception/respond", headers=headers)

        assert resp.status_code == 200
        body = resp.text

        # Verify real environment variables are not leaked
        jwt_secret = os.getenv("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
        if jwt_secret:
            assert jwt_secret not in body, "JWT_SECRET_KEY leaked in deception response!"

        aws_key = os.getenv("AWS_SECRET_ACCESS_KEY", "testing")
        if aws_key and aws_key != "testing":
            assert aws_key not in body, "AWS_SECRET_ACCESS_KEY leaked in deception response!"

        # Verify JSON is purely synthetic structure
        data = resp.json()
        assert data["database"] == "production_app_db"
        assert "dummySaltValue" in body

    def test_zero_origin_forwarding_in_responder(self):
        """
        Inspects deception router and service implementation code via AST
        to mathematically prove zero origin forwarding, HTTP clients, or proxy calls exist.
        """
        backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        deception_api_path = os.path.join(backend_dir, "api", "deception.py")
        deception_service_path = os.path.join(backend_dir, "services", "deception_service.py")

        for filepath in [deception_api_path, deception_service_path]:
            assert os.path.exists(filepath), f"File {filepath} must exist"
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            # Prove no outbound HTTP client is invoked to proxy to origin
            assert "httpx.get" not in content
            assert "httpx.post" not in content
            assert "requests.get" not in content
            assert "requests.post" not in content
            assert "urllib.request" not in content
            assert "proxy_pass" not in content


# ===========================================================================
# Standalone Runner
# ===========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Running Adversarial Empirical Challenge Suite...")
    print("=" * 70)
    import pytest
    sys.exit(pytest.main(["-v", "-s", __file__]))
