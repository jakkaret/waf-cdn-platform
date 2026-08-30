"""
Shared pytest fixtures for the backend test suite.

Ruling R3 (task-7-brief.md): tests run in-process against
fastapi.testclient.TestClient, with every external store faked at its
service boundary. No live DynamoDB, ClickHouse, or Redis is required, and no
network call is allowed to leave the machine.

Strategy
--------
1. Force a handful of dummy environment variables *before* any application
   module is imported, so:
   - boto3 DynamoDB "resource" construction (lazy, no network by itself)
     never accidentally talks to real AWS if it isn't overridden below, and
   - any accidental real DynamoDB call that slips through (e.g. BOLAGuard's
     import-time policy load in services/bola_guard.py) fails instantly
     against an unused loopback port instead of reaching the internet.
2. Provide a tiny in-memory stand-in for the DynamoDB table operations the
   production code actually calls (get_item/put_item/scan/query/update_item/
   delete_item), shared through a module-level store that is cleared before
   every test.
3. In an autouse fixture, monkeypatch the *already-imported* singletons
   (api.auth.auth_service, services.rbac.auth_service, services.origin_service.db,
   api.rules.rule_manager) so their tables/paths point at the fakes, and
   monkeypatch services.dynamodb_service.DynamoDBService itself so that any
   fresh construction (e.g. services.rbac.verify_origin_ownership's local
   `from services.dynamodb_service import DynamoDBService`) also lands on
   the fake, sharing the same backing store.
4. Build a *minimal* FastAPI test app containing only the routers under
   test (auth, origins, rules, ai_summary) rather than importing
   dashboard/backend/main.py, which also wires up Telegram/Cloudflare/ML
   singletons and background asyncio workers that have nothing to do with
   these five scenarios and would otherwise need faking too.
"""
import os
import re
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 1. Environment must be nailed down before *any* api/services module import.
#    dotenv's load_dotenv() (called by several modules) never overrides an
#    already-set variable, so setting these first also shields the suite from
#    a real dashboard/backend/../.env (or CI's own env) leaking in.
# ---------------------------------------------------------------------------
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
# Unused loopback port: any DynamoDB call that isn't faked below fails
# instantly with "connection refused" instead of reaching real AWS.
os.environ["DYNAMODB_ENDPOINT_URL"] = "http://127.0.0.1:1"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-pytest-only"
os.environ["WAF_CONTAINER_NAME"] = "test-waf-container-does-not-exist"
os.environ["GEMINI_API_KEY"] = ""
os.environ.setdefault("ORIGINS_QUOTA_DEFAULT", "5")

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from boto3.dynamodb.conditions import And, Or, Equals  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402

from services.rate_limiter import limiter  # noqa: E402
from services.dynamodb_service import DynamoDBService  # noqa: E402
import services.dynamodb_service as dynamodb_service_module  # noqa: E402
import services.origin_service as origin_service_module  # noqa: E402
import services.rbac as rbac_module  # noqa: E402

from api import auth as auth_module  # noqa: E402
from api import origins as origins_module  # noqa: E402
from api import rules as rules_module  # noqa: E402
from api import ai_summary as ai_summary_module  # noqa: E402


# ---------------------------------------------------------------------------
# Generic in-memory stand-in for the DynamoDB table operations the
# production code calls. Not a general-purpose DynamoDB emulator: it only
# understands Key/Attr .eq() and And/Or combinations (all this codebase
# uses), and "SET a = :x, b = :y[, ...] [REMOVE c[, d...]]" update
# expressions (the only shape used anywhere in services/*.py).
# ---------------------------------------------------------------------------

def _eval_condition(cond, item):
    if isinstance(cond, And):
        left, right = cond._values
        return _eval_condition(left, item) and _eval_condition(right, item)
    if isinstance(cond, Or):
        left, right = cond._values
        return _eval_condition(left, item) or _eval_condition(right, item)
    if isinstance(cond, Equals):
        attr, value = cond._values
        return item.get(attr.name) == value
    raise NotImplementedError(f"Unsupported fake-table condition: {type(cond)!r}")


def _apply_update_expression(item, expr, attr_values=None, attr_names=None):
    attr_values = attr_values or {}
    attr_names = attr_names or {}

    set_part, remove_part = expr, None
    if " REMOVE " in expr:
        set_part, remove_part = expr.split(" REMOVE ", 1)
    set_part = set_part.strip()
    if set_part.startswith("SET "):
        set_part = set_part[len("SET "):]

    if set_part.strip():
        for assignment in set_part.split(","):
            assignment = assignment.strip()
            if not assignment:
                continue
            name_tok, val_tok = (p.strip() for p in assignment.split("=", 1))
            name = attr_names.get(name_tok, name_tok)
            value = attr_values.get(val_tok, val_tok)
            item[name] = value

    if remove_part:
        for name_tok in remove_part.split(","):
            name_tok = name_tok.strip()
            if not name_tok:
                continue
            item.pop(attr_names.get(name_tok, name_tok), None)

    return item


class InMemoryTable:
    """Stands in for a boto3 DynamoDB Table resource, backed by a shared list."""

    def __init__(self, rows):
        self.rows = rows  # shared list object; only ever mutated in place

    def put_item(self, Item):
        self.rows.append(dict(Item))
        return {}

    def get_item(self, Key):
        for row in self.rows:
            if all(row.get(k) == v for k, v in Key.items()):
                return {"Item": row}
        return {}

    def scan(self, FilterExpression=None, Limit=None, ExclusiveStartKey=None, **_kwargs):
        items = list(self.rows)
        if FilterExpression is not None:
            items = [i for i in items if _eval_condition(FilterExpression, i)]
        if Limit:
            items = items[:Limit]
        return {"Items": items}

    def query(self, KeyConditionExpression=None, IndexName=None, **_kwargs):
        items = list(self.rows)
        if KeyConditionExpression is not None:
            items = [i for i in items if _eval_condition(KeyConditionExpression, i)]
        return {"Items": items}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues=None,
                     ExpressionAttributeNames=None, **_kwargs):
        for row in self.rows:
            if all(row.get(k) == v for k, v in Key.items()):
                _apply_update_expression(row, UpdateExpression, ExpressionAttributeValues,
                                          ExpressionAttributeNames)
                return {}
        return {}

    def delete_item(self, Key):
        for i, row in enumerate(self.rows):
            if all(row.get(k) == v for k, v in Key.items()):
                self.rows.pop(i)
                break
        return {}


# table name -> list[dict]; cleared before every test by the autouse fixture.
_STORE: dict = {}


def _table(name: str) -> InMemoryTable:
    _STORE.setdefault(name, [])
    return InMemoryTable(_STORE[name])


class FakeDynamoDBService(DynamoDBService):
    """
    Real DynamoDBService business logic (create_origin, get_origins_by_user,
    update_origin, ...) reused unchanged -- only __init__ is overridden, to
    swap the boto3-backed tables for InMemoryTable instances instead of
    reimplementing that logic in the test suite.
    """

    def __init__(self):  # noqa: super() intentionally not called - no boto3 here
        self.region = "test"
        self.alerts_table_name = "waf_alerts"
        self.logs_table_name = "waf_logs"
        self.rules_table_name = "waf_rules"
        self.users_table_name = "waf_users"
        self.alerts_table = _table("waf_alerts")
        self.logs_table = _table("waf_logs")
        self.rules_table = _table("waf_rules")
        self.waf_users = _table("waf_users")
        self.origins_table = _table("waf_origins")
        self.domains_table = _table("waf_domains")
        self.ssl_certs_table = _table("waf_ssl_certs")
        self.pending_rules_table = _table("waf_pending_rules")


@pytest.fixture(autouse=True)
def fake_infrastructure(monkeypatch, tmp_path):
    """Patch every external-store singleton at its service boundary (Ruling R3)."""
    _STORE.clear()

    # DynamoDB: patch the class itself so any fresh construction (e.g. the
    # local import inside services.rbac.verify_origin_ownership) also lands
    # on the fake and shares the same backing store as origin_service.db.
    monkeypatch.setattr(dynamodb_service_module, "DynamoDBService", FakeDynamoDBService)
    monkeypatch.setattr(origin_service_module, "db", FakeDynamoDBService())

    # Auth: both api.auth's and services.rbac's AuthService singletons must
    # see the same users, so point both at the same backing list.
    monkeypatch.setattr(auth_module.auth_service, "users_table", _table("waf_users"))
    monkeypatch.setattr(rbac_module.auth_service, "users_table", _table("waf_users"))

    # Rule files/nginx: rule_manager is instantiated at import time against
    # the *real* modsecurity/custom-rules directory, and reload/test shell
    # out to `docker exec` against WAF_CONTAINER_NAME, which does not exist
    # here. Redirect writes to a throwaway directory and no-op the two
    # docker-exec-backed calls.
    monkeypatch.setattr(rules_module.rule_manager, "rules_dir", str(tmp_path))
    monkeypatch.setattr(rules_module.rule_manager, "test_nginx", lambda: None)
    monkeypatch.setattr(rules_module.rule_manager, "reload_nginx", lambda: None)

    # Rate limiter storage is a module-level singleton shared across the
    # whole test session; reset it so one test's register/login calls never
    # trip another test's 5-per-minute/10-per-minute limits.
    limiter.reset()

    yield


@pytest.fixture()
def app() -> FastAPI:
    """A minimal app wired with just the routers these scenarios exercise."""
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    test_app.include_router(auth_module.router)
    test_app.include_router(origins_module.router)
    test_app.include_router(rules_module.router)
    test_app.include_router(ai_summary_module.router)
    return test_app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


DEFAULT_PASSWORD = "Sup3rSecret!"


@pytest.fixture()
def default_password() -> str:
    return DEFAULT_PASSWORD


@pytest.fixture()
def register_user(client: TestClient):
    """Factory fixture: register_user(email, username, role="viewer") -> body dict.

    Note: the *first* user ever registered against a given fake store always
    becomes admin (api/auth.py's own bootstrap rule), regardless of the role
    requested here.
    """

    def _register(email: str, username: str, role: str = "viewer",
                   password: str = DEFAULT_PASSWORD) -> dict:
        resp = client.post(
            "/api/auth/register",
            json={"email": email, "username": username, "password": password, "role": role},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    return _register


@pytest.fixture()
def auth_header():
    def _header(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    return _header
