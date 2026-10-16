"""Re-audit 2026-10-17: every backend path meant only for nginx/frps/control-api
is answered 404 on the public Caddy vhosts."""
import re
from pathlib import Path

CADDY = (Path(__file__).resolve().parents[3] / "nginx/Caddyfile").read_text()


def test_internal_paths_blocked_on_public_vhosts():
    m = re.search(r"@internal_ml_relay path ([^\n]+)", CADDY)
    paths = set(m.group(1).split())
    assert {"/api/ml/shadow/decision*", "/api/ml/capture*", "/api/tunnels/frp-hook*",
            "/api/deception/respond*"} <= paths
    assert "respond @internal_ml_relay 404" in CADDY
    # every dashboard site block imports it
    blocks = CADDY.count("reverse_proxy http://host.docker.internal:8000")
    assert CADDY.count("import internal_ml_relay") >= 1 and blocks >= 1
