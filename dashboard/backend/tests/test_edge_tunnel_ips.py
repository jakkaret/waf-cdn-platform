"""The edges reach Main over WireGuard (deploy/wireguard/README.md): their
traffic then arrives from 10.88.0.2/10.88.0.3 instead of their public IPs.
Every source-IP check that trusts an edge must accept those addresses, or the
switch silently breaks something:

- set_real_ip_from (nginx realip, P2.5): every visitor would get the edge's
  tunnel address as the client address, so the rate limiter and CAPTCHA
  treat all visitors as one client and origins get the wrong X-Real-IP;
- /api/cdn/logs/ingest: edge logs stop arriving (404);
- log_forward.KNOWN_EDGE_IPS: edge traffic is counted twice;
- control-api EDGE_ALLOWED_IPS: rule sync gets 403 and curl -f fails quietly.
"""
import re
import sys
from pathlib import Path

from api import cdn as cdn_module
from services.edge_tunnel import EDGE_TUNNEL_IPS
from services.log_forward import KNOWN_EDGE_IPS

REPO = Path(__file__).resolve().parents[3]
MAIN_TUNNEL_IP = "10.88.0.1"


def _geo_trusted():
    text = (REPO / "nginx/templates/conf.d/default.conf.template").read_text()
    return set(re.findall(r"^set_real_ip_from\s+([0-9a-f.:/]+);", text, re.M))


def _control_api_default():
    text = (REPO / "cdn/control-api/main.py").read_text()
    raw = re.search(r'"EDGE_ALLOWED_IPS",\s*"([^"]+)"', text).group(1)
    return {ip.strip() for ip in raw.split(",")}


def test_tunnel_ips_are_the_two_edges_not_main():
    assert EDGE_TUNNEL_IPS == {"10.88.0.2", "10.88.0.3"}
    assert MAIN_TUNNEL_IP not in EDGE_TUNNEL_IPS


def test_nginx_trusts_edge_tunnel_ips_for_x_real_ip():
    trusted = _geo_trusted()
    assert EDGE_TUNNEL_IPS <= trusted
    assert MAIN_TUNNEL_IP not in trusted
    assert not any(t.startswith("10.88.0.0/") for t in trusted)


def test_log_ingest_accepts_edge_tunnel_ips():
    assert EDGE_TUNNEL_IPS <= cdn_module._KNOWN_EDGE_FORWARDER_IPS
    assert MAIN_TUNNEL_IP not in cdn_module._KNOWN_EDGE_FORWARDER_IPS


def test_main_log_tail_skips_edge_tunnel_ips():
    assert EDGE_TUNNEL_IPS <= KNOWN_EDGE_IPS
    assert MAIN_TUNNEL_IP not in KNOWN_EDGE_IPS


def test_control_api_default_allows_edge_tunnel_ips():
    allowed = _control_api_default()
    assert EDGE_TUNNEL_IPS <= allowed
    assert MAIN_TUNNEL_IP not in allowed


def test_nginx_trusts_only_the_edges():
    """P2.5 (H81): the docker network (test containers on waf-net) is no
    longer allowed to set the client address."""
    assert _geo_trusted() == {"45.154.26.91", "57.158.25.236"} | EDGE_TUNNEL_IPS
    text = (REPO / "nginx/templates/conf.d/default.conf.template").read_text()
    assert re.search(r"^real_ip_header X-Real-IP;", text, re.M)
    assert "real_ip_recursive on" not in text
