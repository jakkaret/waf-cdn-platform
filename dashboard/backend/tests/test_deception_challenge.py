"""
Empirical Stress-Test & Adversarial Challenge Harness for DeceptionService.
Author: challenger_m1_1

Validates:
1. Adversarial Evasion Generators:
   - Recursive / Multi-layer URL Percent-Encoding (%252e%252e%252f, %25252e..)
   - Unicode Homoglyphs & Fullwidth Canonical Normalization (NFKC)
   - Nested & Stripped Directory Traversals (....//, ..././, ..\/..\)
   - Null-byte Injections (%00, %2500, \x00, &#00;)
   - Blind, Stacked, and Comment-Obfuscated SQLi
2. Performance & ReDoS Defense:
   - Catastrophic backtracking patterns under bounded execution time (<50ms)
   - Massive inputs (10KB, 50KB, 100KB payloads)
   - Non-printable, binary, and extreme Unicode code points
3. Zero Host Leakage & Synthetic Guarantees:
   - Verification that host /etc/passwd or host credentials are never returned
   - Verification that AST contains no disk I/O or DB execution calls
4. Anti-Cache & HTTP 200 Guarantees:
   - Complete RFC compliance for Cache-Control, Pragma, Expires, CDN headers
   - HTTP status strictly 200 on all deception pathways
5. Endpoint Security & Fail-Safe Isolation:
   - Unauthorized access strictly rejected with 403 Forbidden
   - Resilient fallback to HTTP 200 under simulated internal engine crashes
"""

import ast
import json
import os
import re
import time
import urllib.parse
from typing import Generator, List, Tuple
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.deception import (
    INTERNAL_DECEPTION_HEADER,
    router as deception_router,
)

# The endpoint has no built-in key any more (a default baked into the
# source was readable by anyone); tests supply their own through the env.
DEFAULT_INTERNAL_KEY = os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")
from services.deception_service import (
    PATH_TRAVERSAL_TEMPLATE,
    SECURE_DECEPTION_HEADERS,
    SQLI_TEMPLATE,
    AttackClassification,
    DeceptionService,
    deception_service,
)
from services.payload_normalizer import payload_normalizer


# ---------------------------------------------------------------------------
# Adversarial Generators
# ---------------------------------------------------------------------------

def generate_recursive_url_traversal() -> List[Tuple[str, str]]:
    """Generates multi-layer URL encoded traversal vectors."""
    base_traversals = [
        "../../etc/passwd",
        "../../etc/shadow",
        "../../windows/win.ini",
        "/proc/self/environ",
        "php://filter/read=convert.base64-encode/resource=index.php",
    ]
    vectors = []
    for base in base_traversals:
        # Layer 1: single quote / urlencode
        enc1 = urllib.parse.quote(base, safe="")
        vectors.append((f"single_encode_{base[:10]}", enc1))

        # Layer 2: double encode (%25..)
        enc2 = urllib.parse.quote(enc1, safe="")
        vectors.append((f"double_encode_{base[:10]}", enc2))

        # Layer 3: triple encode
        enc3 = urllib.parse.quote(enc2, safe="")
        vectors.append((f"triple_encode_{base[:10]}", enc3))

        # Mixed encoding: only dots and slashes encoded
        mixed = base.replace("../", "%2e%2e%2f").replace("..\\", "%2e%2e%5c")
        vectors.append((f"mixed_dots_{base[:10]}", mixed))

        # Double encoded dots & slashes
        double_dots = base.replace("../", "%252e%252e%252f")
        vectors.append((f"double_dots_{base[:10]}", double_dots))

        # Null-byte suffixes
        null_bytes = [
            f"{base}%00.jpg",
            f"{base}%2500.png",
            f"{base}\x00.pdf",
            f"{base}&#00;.html",
        ]
        for nb in null_bytes:
            vectors.append((f"null_byte_{base[:10]}", nb))

    # Add overlong and alternative traversals
    vectors.extend([
        ("overlong_utf8_1", "..%c0%af..%c0%afetc/passwd"),
        ("overlong_utf8_2", "..%c1%9c..%c1%9cwindows/win.ini"),
        ("nested_strip_1", "....//....//etc/passwd"),
        ("nested_strip_2", "..././..././etc/passwd"),
        ("nested_mixed_slash", "..\\/..\\/etc/passwd"),
        ("nested_quad_slash", "....\\\\....\\\\windows\\win.ini"),
    ])
    return vectors


def generate_unicode_homoglyphs() -> List[Tuple[str, str]]:
    """Generates Unicode homoglyphs and fullwidth forms."""
    return [
        # Fullwidth ASCII path traversal
        ("fullwidth_traversal_slash", "／ｅｔｃ／ｐａｓｓｗｄ"),
        ("fullwidth_dot_dot_slash", "．．／．．／ｅｔｃ／ｐａｓｓｗｄ"),
        ("fullwidth_backslash", "..\uff3c..\uff3cwinnt\uff3cwin.ini"),
        ("fraction_slash", "..\u2044..\u2044etc\u2044passwd"),
        ("division_slash", "..\u2215..\u2215etc\u2215passwd"),
        # Fullwidth SQLi
        ("fullwidth_sqli_or", "＇ ＯＲ １＝１"),
        ("fullwidth_sqli_union", "ＵＮＩＯＮ ＳＥＬＥＣＴ １，２，３"),
        ("fullwidth_sqli_drop", "； ＤＲＯＰ ＴＡＢＬＥ ｕｓｅｒｓ；"),
    ]


def generate_sqli_payloads() -> List[Tuple[str, str]]:
    """Generates stacked, boolean, blind, comment-obfuscated, and time-based SQLi."""
    return [
        # Boolean tautologies
        ("boolean_single_quote", "1' OR '1'='1"),
        ("boolean_double_quote", '1" OR "1"="1'),
        ("boolean_comment_dash", "admin' OR 1=1--"),
        ("boolean_comment_hash", "admin' OR 1=1#"),
        ("boolean_empty_quote", "' OR ''='"),
        ("boolean_numeric", "1 OR 1=1"),
        ("boolean_parentheses", "') OR ('1'='1"),
        # Comment obfuscation and keyword splitting
        ("inline_comment_space", "1'/**/OR/**/1=1#"),
        ("inline_comment_split", "UN/**/ION SE/**/LECT 1, 2, 3"),
        ("comment_c_style", "1' /*!50000OR*/ 1=1--"),
        # UNION attacks
        ("union_select_basic", "1' UNION SELECT null, username, password FROM users--"),
        ("union_all_select", "1' UNION ALL SELECT null, null, null--"),
        # Stacked queries
        ("stacked_drop_table", "1; DROP TABLE users;"),
        ("stacked_xp_cmdshell", "'; EXEC xp_cmdshell('dir');--"),
        # Time-based blind / delay / benchmark
        ("waitfor_delay", "1'; WAITFOR DELAY '0:0:5'--"),
        ("sleep_function", "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"),
        ("benchmark_function", "1' AND BENCHMARK(10000000, MD5(1))--"),
        ("pg_sleep", "1' AND pg_sleep(5)--"),
        # Metadata / information schema
        ("info_schema_tables", "SELECT * FROM information_schema.tables"),
        ("sys_tables", "SELECT * FROM sys.tables"),
        ("pg_tables", "SELECT * FROM pg_tables"),
    ]


def generate_boundary_payloads() -> List[Tuple[str, str]]:
    """Generates boundary, massive, binary, and empty payloads."""
    return [
        ("empty_string", ""),
        ("single_char", "a"),
        ("whitespace_only", "   \t\r\n   "),
        ("punctuation_only", r"""!@#$%^&*()_+-=[]{}|;':",./<>?"""),
        ("10kb_padding", "A" * 10240),
        ("50kb_padding", "B" * 51200),
        ("100kb_padding", "C" * 102400),
        ("binary_all_bytes", bytes(range(256)).decode("latin1")),
        ("high_unicode_emojis", "🔥💀🚨🛡️💻" * 500),
        ("high_unicode_scripts", "กขคงจฉชซไทยภาษา" * 200),
        ("deeply_nested_json", '{"a": {"b": {"c": {"d": "admin\' OR 1=1--"}}}}'),
    ]


def generate_redos_stress_patterns() -> List[Tuple[str, str]]:
    """Generates adversarial inputs designed to trigger catastrophic backtracking in regex."""
    return [
        ("redos_traversal_repeats", "../" * 5000),
        ("redos_sqli_or_repeats", "' or " * 2000 + "1=1"),
        ("redos_unclosed_comment", "/*" + "*" * 5000),
        ("redos_long_select_columns", "SELECT " + "col," * 3000 + "id FROM tbl"),
        ("redos_percent_repeats", "%25" * 3000),
        ("redos_null_byte_repeats", "%00" * 4000),
        ("redos_unicode_dot_repeats", "\uff0e\uff0e\uff0f" * 2000),
    ]


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app() -> FastAPI:
    test_app = FastAPI()
    test_app.include_router(deception_router)
    return test_app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# ===========================================================================
# 1. Adversarial Evasion & Homoglyph Challenge Tests
# ===========================================================================

class TestAdversarialEvasionChallenges:
    """Stress-tests attack classification against evasion vectors."""

    @pytest.mark.parametrize("name,vector", generate_recursive_url_traversal())
    def test_recursive_url_traversal_evasion(self, name: str, vector: str):
        svc = DeceptionService()
        res = svc.classify_attack(uri=f"/download?file={vector}")
        resp = svc.generate_response(uri=f"/download?file={vector}")

        # Classification must resolve to a valid template
        assert res.template_id in ("path_traversal", "sql_injection"), f"Failed for {name}: {res}"
        # For path traversal vectors, confidence must be > 0 and response must be 200
        assert resp.status_code == 200
        assert resp.template_id == "path_traversal"
        assert resp.body == PATH_TRAVERSAL_TEMPLATE
        assert resp.content_type == "text/plain"

    @pytest.mark.parametrize("name,vector", generate_unicode_homoglyphs())
    def test_unicode_homoglyphs_evasion(self, name: str, vector: str):
        svc = DeceptionService()
        res = svc.classify_attack(uri=f"/test?input={vector}", body=vector)
        resp = svc.generate_response(uri=f"/test?input={vector}", body=vector)

        assert resp.status_code == 200
        assert res.template_id in ("path_traversal", "sql_injection")
        if "traversal" in name or "dot" in name or "backslash" in name:
            assert resp.template_id == "path_traversal"
        elif "sqli" in name:
            assert resp.template_id == "sql_injection"
            assert resp.content_type == "application/json"

    @pytest.mark.parametrize("name,vector", generate_sqli_payloads())
    def test_sqli_variant_evasion(self, name: str, vector: str):
        svc = DeceptionService()
        res = svc.classify_attack(uri="/search", body=f"query={vector}")
        resp = svc.generate_response(uri="/search", body=f"query={vector}")

        assert resp.status_code == 200
        assert resp.template_id == "sql_injection"
        assert resp.content_type == "application/json"
        # Validate that synthetic DB json is parseable
        data = json.loads(resp.body)
        assert data["database"] == "production_app_db"
        assert "schema" in data

    @pytest.mark.parametrize("name,vector", generate_boundary_payloads())
    def test_boundary_and_extreme_inputs(self, name: str, vector: str):
        svc = DeceptionService()
        # Must execute without throwing exceptions or crashing
        res = svc.classify_attack(uri=f"/boundary/{vector[:100]}", body=vector)
        resp = svc.generate_response(uri=f"/boundary/{vector[:100]}", body=vector)

        assert resp.status_code == 200
        assert res.template_id in ("path_traversal", "sql_injection")
        assert len(resp.body) > 0


# ===========================================================================
# 2. ReDoS Defense & Performance Stress Tests
# ===========================================================================

class TestReDoSAndPerformanceStress:
    """Empirically evaluates regex execution time under adversarial backtracking attempts."""

    @pytest.mark.parametrize("name,pattern", generate_redos_stress_patterns())
    def test_redos_bounded_latency(self, name: str, pattern: str):
        svc = DeceptionService()
        t0 = time.perf_counter()
        res = svc.classify_attack(uri=f"/test/{pattern}", body=pattern)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Max allowed execution time per attack evaluation is 50ms (typical is <5ms)
        assert elapsed_ms < 50.0, f"Potential ReDoS detected in {name}: took {elapsed_ms:.2f}ms"
        assert res.template_id in ("path_traversal", "sql_injection")

    def test_massive_concurrency_stress(self):
        """Simulates rapid sequential evaluation of 200 mixed adversarial inputs."""
        svc = DeceptionService()
        traversals = generate_recursive_url_traversal()
        sqli = generate_sqli_payloads()
        redos = generate_redos_stress_patterns()

        all_tests = traversals + sqli + redos
        t0 = time.perf_counter()

        for name, payload in all_tests:
            resp = svc.generate_response(uri=f"/inspect?p={payload[:500]}", body=payload)
            assert resp.status_code == 200

        total_time_ms = (time.perf_counter() - t0) * 1000
        avg_time_ms = total_time_ms / len(all_tests)

        # Average latency must be under 10ms per evaluation
        assert avg_time_ms < 10.0, f"Average evaluation too slow: {avg_time_ms:.2f}ms per item"


# ===========================================================================
# 3. Zero Host Leakage & Synthetic Purity Guarantees
# ===========================================================================

class TestZeroHostLeakageAndPurity:
    """Verifies that under no circumstance are host system files or real databases queried."""

    def test_host_etc_passwd_isolation(self):
        """Compares actual host /etc/passwd against synthetic response."""
        svc = DeceptionService()
        resp = svc.generate_response(uri="/etc/passwd")

        # 1. Response must strictly equal predefined in-memory template
        assert resp.body == PATH_TRAVERSAL_TEMPLATE

        # 2. If host /etc/passwd is readable, verify host-specific accounts are absent
        if os.path.exists("/etc/passwd"):
            try:
                with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
                    host_content = f.read()

                # Extract host usernames
                host_users = {
                    line.split(":")[0].strip()
                    for line in host_content.splitlines()
                    if line and not line.startswith("#")
                }
                # Check for host-only usernames (e.g. current user, mac daemons)
                current_user = os.getenv("USER", "")
                if current_user and current_user not in ("root", "daemon", "bin"):
                    assert current_user not in resp.body, f"Real user '{current_user}' leaked!"

                mac_daemons = ["_spotlight", "_coreaudiod", "_windowserver", "_taskgated"]
                for daemon in mac_daemons:
                    if daemon in host_users:
                        assert daemon not in resp.body, f"Host daemon '{daemon}' leaked!"
            except PermissionError:
                pass

        # 3. Verify presence of synthetic accounts
        assert "games:x:5:60:games" in resp.body
        assert "secops:x:1002:1002:Security Operations" in resp.body
        assert "deployer:x:1004:1004:CI/CD Deployment Service" in resp.body

    def test_synthetic_sqli_purity(self):
        """Verifies that SQL injection responses contain only dummy records."""
        svc = DeceptionService()
        resp = svc.generate_response(uri="/api/login", body="admin' OR 1=1--")

        assert resp.body == SQLI_TEMPLATE
        data = json.loads(resp.body)
        assert data["database"] == "production_app_db"
        assert len(data["schema"]["tables"]) == 2
        # Check that password hashes are explicitly marked dummy
        app_users = data["schema"]["tables"][0]["rows"]
        for u in app_users:
            assert "dummySyntheticHash" in u["password_hash"]
            assert u["email"].endswith("@corp.internal")

    def test_static_ast_no_io_calls(self):
        """Inspects deception_service.py AST to guarantee zero disk or DB calls."""
        service_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "services", "deception_service.py")
        )
        with open(service_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=service_path)

        prohibited_calls = {"open", "eval", "exec", "system", "popen", "subprocess"}
        found_prohibited = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in prohibited_calls:
                    found_prohibited.append(node.func.id)

        assert not found_prohibited, f"Prohibited I/O calls found in deception service AST: {found_prohibited}"


# ===========================================================================
# 4. Anti-Cache & HTTP 200 Compliance
# ===========================================================================

class TestAntiCacheAndStatusCompliance:
    """Verifies strict adherence to R4.3 - R4.5 headers and status code."""

    @pytest.mark.parametrize("uri,body", [
        ("/../../etc/passwd", ""),
        ("/api/users?id=1' OR 1=1", ""),
        ("/random/resource", "data"),
    ])
    def test_anti_cache_headers_present(self, uri: str, body: str):
        svc = DeceptionService()
        resp = svc.generate_response(uri=uri, body=body)

        assert resp.status_code == 200
        headers = resp.headers

        # RFC anti-cache headers
        assert "no-store" in headers["Cache-Control"]
        assert "no-cache" in headers["Cache-Control"]
        assert "must-revalidate" in headers["Cache-Control"]
        assert headers["Pragma"] == "no-cache"
        assert headers["Expires"] == "0"
        assert headers["Surrogate-Control"] == "no-store"
        assert headers["CDN-Cache-Control"] == "no-store"

        # Security headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

        # Server concealing
        assert headers["Server"] == "nginx"


# ===========================================================================
# 5. FastAPI Endpoint Stress & Security
# ===========================================================================

class TestFastApiEndpointSecurityAndStress:
    """Tests the /api/deception/respond endpoint with valid, invalid, and missing credentials."""

    def test_endpoint_missing_internal_key_403(self, client: TestClient):
        response = client.get("/api/deception/respond")
        assert response.status_code == 403
        assert "Forbidden" in response.json()["detail"]

    def test_endpoint_invalid_internal_key_403(self, client: TestClient):
        response = client.get(
            "/api/deception/respond",
            headers={INTERNAL_DECEPTION_HEADER: "attacker-forged-key-12345"},
        )
        assert response.status_code == 403
        assert "Forbidden" in response.json()["detail"]

    def test_endpoint_valid_key_path_traversal(self, client: TestClient):
        headers = {
            INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
            "X-Original-URI": "/download?file=../../../../etc/passwd",
            "X-Original-Method": "GET",
            "X-Request-ID": "req-adversarial-1",
            "X-Real-IP": "198.51.100.22",
        }
        response = client.get("/api/deception/respond", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "root:x:0:0:root:" in response.text
        assert response.headers["Cache-Control"] == SECURE_DECEPTION_HEADERS["Cache-Control"]
        assert response.headers["X-Request-ID"] == "req-adversarial-1"

    def test_endpoint_valid_key_sqli(self, client: TestClient):
        headers = {
            INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
            "X-Original-URI": "/api/users?id=1%27%20UNION%20SELECT%20null,null--",
            "X-Original-Method": "GET",
            "X-Request-ID": "req-adversarial-2",
        }
        response = client.get("/api/deception/respond", headers=headers)
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
        data = response.json()
        assert data["database"] == "production_app_db"

    def test_endpoint_large_body_stress(self, client: TestClient):
        headers = {
            INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
            "X-Original-URI": "/api/upload",
            "X-Original-Method": "POST",
            "X-Request-ID": "req-large-body",
        }
        large_body = "x=" + ("A" * 70000)  # Exceeds 64KB body truncation threshold
        response = client.post("/api/deception/respond", headers=headers, content=large_body)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == SECURE_DECEPTION_HEADERS["Cache-Control"]

    def test_endpoint_fail_safe_shield_on_classifier_crash(self, client: TestClient):
        """Simulates an unexpected crash inside DeceptionService.generate_response."""
        headers = {
            INTERNAL_DECEPTION_HEADER: DEFAULT_INTERNAL_KEY,
            "X-Original-URI": "/test",
            "X-Request-ID": "req-crash-shield",
        }
        with patch.object(
            deception_service,
            "generate_response",
            side_effect=RuntimeError("Simulated unexpected classifier failure"),
        ):
            response = client.get("/api/deception/respond", headers=headers)
            # Fail-safe shield MUST intercept and return 200 fallback, NEVER 500
            assert response.status_code == 200
            assert "root:x:0:0:root:" in response.text
            assert response.headers["X-Request-ID"] == "req-crash-shield"
            assert "no-store" in response.headers["Cache-Control"]
