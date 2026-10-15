"""H12/H82: Redis and ClickHouse must not listen on public interfaces, Redis
needs a password, and control-api is published only on loopback and Main's
WireGuard address (the edges reach it through the tunnel)."""
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
SERVICES = yaml.safe_load((REPO / "docker-compose.yml").read_text())["services"]


def _host(port):
    m = re.match(r"(\d+\.\d+\.\d+\.\d+):", port)
    return m.group(1) if m else "0.0.0.0"


def _hosts(service):
    return {_host(p) for p in SERVICES[service].get("ports", [])}


def _calls(text, name):
    """Argument text of every name(...) call, with nested parentheses."""
    out, start = [], 0
    while (i := text.find(name + "(", start)) != -1:
        depth, j = 0, i + len(name)
        while True:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            if depth == 0:
                break
            j += 1
        out.append(text[i + len(name) + 1:j])
        start = j
    return out


def test_redis_and_clickhouse_are_loopback_only():
    assert _hosts("redis") == {"127.0.0.1"}
    assert _hosts("clickhouse") == {"127.0.0.1"}


def test_control_api_is_loopback_and_wireguard_only():
    assert _hosts("control-api") == {"127.0.0.1", "10.88.0.1"}


def test_no_service_publishes_on_all_interfaces_except_the_public_entry_points():
    # waf (edges -> 8080 is filtered by DOCKER-USER) and caddy (80/443) are the
    # only intended public listeners.
    for name, svc in SERVICES.items():
        if name in ("waf", "caddy", "dvwa"):
            continue
        for p in svc.get("ports", []):
            assert _host(p) != "0.0.0.0", f"{name} publishes {p} on all interfaces"


def test_redis_requires_a_password_from_env():
    redis = SERVICES["redis"]
    assert redis["environment"]["REDIS_PASSWORD"].startswith("${REDIS_PASSWORD:?")
    assert "--requirepass" in " ".join(redis["command"])
    assert "$$REDIS_PASSWORD" in " ".join(redis["command"])  # expanded at runtime, not in Cmd
    url = SERVICES["control-api"]["environment"]["REDIS_URL"]
    assert url.startswith("redis://:${REDIS_PASSWORD:?") and url.endswith("@redis:6379/0")


def test_every_dashboard_redis_client_passes_the_password():
    services = REPO / "dashboard/backend/services"
    for path in services.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for call in _calls(text, "redis.Redis"):
            assert "password=" in call, f"{path.name}: redis.Redis without password"
