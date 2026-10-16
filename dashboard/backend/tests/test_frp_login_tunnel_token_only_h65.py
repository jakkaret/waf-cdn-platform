"""H65: the frps Login/NewProxy webhook accepts only tunnel tokens. A
dashboard session JWT is signed with the same key and must not open a tunnel."""
import api.tunnels as tunnels
from services.auth_service import AuthService

svc = AuthService()


def _resolve(token):
    return tunnels._resolve_frp_identity(token)


def test_session_token_is_not_a_tunnel_identity():
    session = svc.create_access_token({"sub": "00000000-0000-0000-0000-000000000001", "role": "viewer"})
    assert _resolve(session)[0] == "none"


def test_typed_token_without_domain_is_rejected():
    t = svc.create_access_token({"sub": "u", "type": "tunnel_token"})
    assert _resolve(t)[0] == "none"


def test_tunnel_token_is_accepted():
    t = svc.create_access_token({"sub": "u", "type": "tunnel_token", "domain": "app.example.com"})
    kind, payload = _resolve(t)
    assert kind == "jwt" and payload["domain"] == "app.example.com"
