"""Re-audit 2026-10-17: per-IP limits key on the visitor, not on the Caddy
container every request arrives from; a direct caller cannot choose its key."""
from types import SimpleNamespace

from services.rate_limiter import client_ip


def _req(peer, xri=None):
    h = {} if xri is None else {"x-real-ip": xri}
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=h)


def test_behind_caddy_each_visitor_gets_its_own_key():
    assert client_ip(_req("172.18.0.5", "203.0.113.7")) == "203.0.113.7"
    assert client_ip(_req("172.18.0.5", "198.51.100.9")) == "198.51.100.9"


def test_untrusted_peer_cannot_spoof_its_key():
    assert client_ip(_req("10.88.0.2", "1.2.3.4")) == "10.88.0.2"
    assert client_ip(_req("203.0.113.50", "1.2.3.4")) == "203.0.113.50"


def test_garbage_header_falls_back_to_peer():
    assert client_ip(_req("127.0.0.1", "not-an-ip")) == "127.0.0.1"
    assert client_ip(_req("172.18.0.5")) == "172.18.0.5"


def test_login_limit_is_per_visitor(app):
    """Five bad logins from one visitor must not lock out another (both via Caddy)."""
    from fastapi.testclient import TestClient
    client = TestClient(app, client=("172.18.0.5", 50000))  # the Caddy container
    a = {"X-Real-IP": "203.0.113.1"}
    b = {"X-Real-IP": "203.0.113.2"}
    body = {"email": "nobody@example.com", "password": "wrong-password"}
    codes_a = [client.post("/api/auth/login", json=body, headers=a).status_code for _ in range(6)]
    assert codes_a[-1] == 429
    assert client.post("/api/auth/login", json=body, headers=b).status_code != 429
