"""F-028: every mutating route the UI treats as admin-only must enforce it
server-side. Viewer token -> 403 (rejected in the dependency, before any
handler body runs); admin token -> passes the gate (422/404, never 401/403,
because the probe sends an empty/invalid body or unknown id)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import auth as auth_module, cdn as cdn_module, ip_rules as ip_module
from api import ml_rules as ml_module, rate_limits as rl_module, rules as rules_module
from api import settings as settings_module, threshold_proposals as tp_module
from services.rate_limiter import limiter

ADMIN_ONLY = [
    # approve/reject/backtest are open to an origin's Owner/Editors for that
    # origin's rules (2026-10-26): see MEMBER_SCOPED below.
    ("DELETE", "/api/ml-rules/abc"),
    ("POST", "/api/ml-rules/reject-legacy"),
    ("POST", "/api/ml-rules/cve-scan"),
    ("GET", "/api/rate-limits/rules"),
    ("GET", "/api/rate-limits/throttled"),
    ("POST", "/api/rate-limits/rules"),
    ("PUT", "/api/rate-limits/rules/abc"),
    ("DELETE", "/api/rate-limits/rules/abc"),
    ("POST", "/api/rate-limits/reset-client"),
    ("GET", "/api/ip-rules/"),
    ("POST", "/api/ip-rules/"),
    ("DELETE", "/api/ip-rules/1.2.3.4"),
    ("POST", "/api/ip-rules/bulk-delete"),
    ("POST", "/api/settings/"),
    ("POST", "/api/rules/"),
    ("PUT", "/api/rules/abc"),
    ("DELETE", "/api/rules/abc"),
    ("POST", "/api/rules/sync"),
]
# Probes safe to run as admin (body validation fails first / unknown id => no side effects)
ADMIN_SAFE = [
    ("GET", "/api/rate-limits/rules"),
    ("GET", "/api/rate-limits/throttled"),
    ("POST", "/api/rate-limits/rules"),
    ("GET", "/api/ip-rules/"),
    ("POST", "/api/ip-rules/"),
    ("POST", "/api/ip-rules/bulk-delete"),
    ("POST", "/api/ml-rules/abc/reject"),
]
# Routes a non-admin reaches only for rules of their own origins; anything
# else is a 404 so a rule's existence does not leak (tests/test_ml_rules_origin_scope.py).
MEMBER_SCOPED = [
    ("POST", "/api/ml-rules/abc/approve"),
    ("POST", "/api/ml-rules/abc/reject"),
    ("POST", "/api/ml-rules/abc/backtest"),
    # tuning proposals belong to one origin and only its Owner decides
    # (2026-10-27, tests/test_threshold_proposal_api.py)
    ("POST", "/api/threshold-proposals/generate?origin_id=abc"),
    ("POST", "/api/threshold-proposals/abc/approve"),
    ("POST", "/api/threshold-proposals/abc/reject"),
    ("POST", "/api/threshold-proposals/abc/rollback"),
]


@pytest.fixture()
def app() -> FastAPI:
    a = FastAPI()
    a.state.limiter = limiter
    for m in (auth_module, cdn_module, ip_module, ml_module, rl_module, rules_module,
              settings_module, tp_module):
        a.include_router(m.router)
    return a


@pytest.fixture()
def client(app):
    return TestClient(app)


@pytest.fixture()
def tokens(client, register_user):
    admin = register_user(email="g-admin@example.com", username="g_admin")
    viewer = register_user(email="g-viewer@example.com", username="g_viewer", role="viewer")
    assert viewer["user"]["role"] == "viewer"
    return admin["access_token"], viewer["access_token"]


def _call(client, method, path, token):
    client.cookies.clear()
    return client.request(method, path, json={}, headers={"Authorization": f"Bearer {token}"})


@pytest.mark.parametrize("method,path", ADMIN_ONLY)
def test_viewer_gets_403(client, tokens, method, path):
    _, viewer = tokens
    assert _call(client, method, path, viewer).status_code == 403


@pytest.mark.parametrize("method,path", ADMIN_SAFE)
def test_admin_passes_the_gate(client, tokens, method, path):
    admin, _ = tokens
    assert _call(client, method, path, admin).status_code not in (401, 403)


@pytest.mark.parametrize("method,path", ADMIN_ONLY + MEMBER_SCOPED)
def test_unauthenticated_gets_401(client, method, path):
    client.cookies.clear()
    assert client.request(method, path, json={}).status_code == 401


@pytest.mark.parametrize("method,path", MEMBER_SCOPED)
def test_a_rule_outside_the_callers_origins_is_404(client, tokens, method, path):
    _, viewer = tokens
    assert _call(client, method, path, viewer).status_code == 404
