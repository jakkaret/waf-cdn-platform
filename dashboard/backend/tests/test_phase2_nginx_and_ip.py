"""Phase 2 of the remediation plan, the parts that live in config text and
the dashboard: every location that reaches an origin is behind the shield
(P2.1), shield-protected responses are no-store (P2.3), the client address
comes from realip only (P2.5), the dead nested rate-limit hook is gone (P2.6)
and the managed host map matches the host the way nginx routes it (H59)."""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
MAIN_TEMPLATE = REPO / "nginx/templates/conf.d/default.conf.template"
ORIGIN_UPSTREAMS = ("frp_tunnel_router", "cloudwaf_tunnel", "dvwa_backend")


def _locations(text: str):
    """(header, body) of every location block, braces balanced."""
    out = []
    for m in re.finditer(r"^\s*location\s+([^{]+)\{", text, re.M):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append((m.group(1).strip(), text[m.end():i - 1]))
    return out


def test_every_location_that_reaches_an_origin_is_behind_the_shield():
    text = MAIN_TEMPLATE.read_text()
    to_origin = [(h, b) for h, b in _locations(text)
                 if any(f"proxy_pass http://{u}" in b for u in ORIGIN_UPSTREAMS)]
    assert len(to_origin) == 10  # five server blocks, "/" and the static-file location each
    for header, body in to_origin:
        assert "auth_request /internal-shield-check;" in body, header
        assert "auth_request_set $shield_protected $upstream_http_x_shield_protected;" in body, header
        assert 'more_set_headers "Cache-Control: $waf_cache_control";' in body, header


def test_shield_protected_responses_are_private_no_store():
    text = MAIN_TEMPLATE.read_text()
    block = re.search(r"map \$shield_protected \$waf_cache_control \{(.*?)\}", text, re.S).group(1)
    assert '"1"     "private, no-store";' in block
    assert "default $upstream_http_cache_control;" in block


def test_deception_fallback_is_never_cached():
    text = MAIN_TEMPLATE.read_text()
    bodies = [b for h, b in _locations(text) if h == "@deception_static"]
    assert len(bodies) == 5 and all('add_header Cache-Control "no-store" always;' in b for b in bodies)


def test_no_nested_rate_limit_hook_is_left():
    for path in (MAIN_TEMPLATE, REPO / "nginx/includes/otp_server.conf",
                 REPO / "nginx/templates/includes/captcha_server.conf.template"):
        text = "\n".join(line for line in path.read_text().splitlines() if not line.strip().startswith("#"))
        assert "auth_request /internal-rate-limit" not in text, path
        assert "limiter/check" not in text, path
        assert "@rate_limit_exceeded" not in text, path


def test_challenge_route_gets_the_retry_after():
    text = (REPO / "nginx/templates/includes/captcha_server.conf.template").read_text()
    cdn_cgi = [b for h, b in _locations(text) if h == "^~ /cdn-cgi/"][0]
    assert "proxy_set_header X-Retry-After $retry_after;" in cdn_cgi


def test_client_address_comes_from_realip_not_a_header_map():
    text = MAIN_TEMPLATE.read_text()
    assert "geo $from_trusted_proxy" not in text
    assert "$http_x_real_ip" not in text
    assert "172.18.0.0/16" not in text


# ------------------------------------------------------- IP rules, log pipeline

def test_ip_block_and_allow_rules_look_at_the_connection_address_only(tmp_path, monkeypatch):
    from services import ip_rule_service as irs
    for name in ("BLOCKLIST_TXT", "WHITELIST_TXT", "BLOCKLIST_CONF", "WHITELIST_CONF"):
        monkeypatch.setattr(irs, name, tmp_path / getattr(irs, name).name)
    service = irs.IPRuleService.__new__(irs.IPRuleService)  # no database needed to render
    service._write_files(["203.0.113.9"], ["198.51.100.1"])
    for conf in (irs.BLOCKLIST_CONF, irs.WHITELIST_CONF):
        text = conf.read_text()
        assert text.count("SecRule REMOTE_ADDR \"@ipMatchFromFile") == 1
        assert "REQUEST_HEADERS" not in text


@pytest.mark.parametrize("line,peer", [
    ({"remote_addr": "203.0.113.5", "realip_remote_addr": "10.88.0.2"}, "10.88.0.2"),
    ({"remote_addr": "10.88.0.3"}, "10.88.0.3"),  # lines written before realip
])
def test_log_tail_identifies_the_edge_by_the_connecting_address(line, peer):
    from services import log_forward
    assert log_forward.peer_addr(line) == peer
    assert peer in log_forward.KNOWN_EDGE_IPS
    entry = log_forward.normalize_access(dict(line, request="GET / HTTP/1.1", status="200"))
    assert entry["edge_node"] == {"10.88.0.2": "edge-th", "10.88.0.3": "edge-asia"}[peer]
    assert entry["ip"] == line["remote_addr"]


def test_access_log_records_the_connecting_address():
    text = (REPO / "nginx/nginx.conf.template").read_text()
    assert '"realip_remote_addr":"$realip_remote_addr"' in text


# ------------------------------------------------------------------- H59

@pytest.mark.parametrize("host", ["shop.example.com", "shop.example.com.", "shop.example.com:443",
                                  "shop.example.com.:8443"])
def test_managed_host_map_matches_every_spelling_nginx_routes(host):
    from services.managed_ruleset import _host_regex
    pattern = _host_regex(["shop.example.com"])
    assert re.match(pattern, host.lower())
    assert not re.match(pattern, "evilshop.example.com")
    assert not re.match(pattern, "shop.example.com.evil.net")
