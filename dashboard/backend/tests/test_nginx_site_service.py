"""services/nginx_site_service.py builds nginx config text and container file
paths from a domain and an origin address, so it must refuse anything that
could add directives, escape conf.d or reach a shell."""
from unittest.mock import MagicMock

import pytest

from services import nginx_site_service as nss

ORIGIN = {"id": "o1", "ip": "203.0.113.10", "port": 8080}


def test_generated_config_uses_the_real_client_ip_everywhere():
    text = nss.generate_site_nginx_config("Shop.Example.com", ORIGIN)
    assert "server_name shop.example.com;" in text
    assert "proxy_pass http://203.0.113.10:8080;" in text
    assert "X-Real-IP $remote_addr" not in text
    assert "proxy_set_header X-Forwarded-For $waf_client_ip;" in text  # rate limiter


@pytest.mark.parametrize("domain", [
    "evil.com; rm -rf /", "a.com\n    location / { return 200; }", "../../etc/passwd",
    "x.com$(id)", "x.com`id`", "a..com", "-a.com", "localhost", "", "a.com/x",
])
def test_bad_domains_are_refused(domain):
    with pytest.raises(ValueError):
        nss.generate_site_nginx_config(domain, ORIGIN)
    with pytest.raises(ValueError):
        nss.deploy_site_route(domain, ORIGIN)
    with pytest.raises(ValueError):
        nss.remove_site_route(domain)


@pytest.mark.parametrize("origin", [
    {"ip": "10.0.0.1; include /etc/passwd", "port": 80},
    {"ip": "10.0.0.1\n}", "port": 80},
    {"ip": "10.0.0.1", "port": "80; x"},
    {"ip": "10.0.0.1", "port": 0},
    {"ip": "10.0.0.1", "port": 70000},
])
def test_bad_origin_addresses_are_refused(origin):
    with pytest.raises(ValueError):
        nss.generate_site_nginx_config("shop.example.com", origin)


def test_hostname_origin_is_accepted():
    assert "proxy_pass http://app.internal.example:3000;" in nss.generate_site_nginx_config(
        "shop.example.com", {"ip": "app.internal.example", "port": 3000})


def test_deploy_writes_without_a_shell(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(nss, "PERSISTENT_SITES_DIR", tmp_path)
    monkeypatch.setattr(nss.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or MagicMock(returncode=0))
    monkeypatch.setattr(nss.rule_mgr, "test_nginx", lambda: None)
    monkeypatch.setattr(nss.rule_mgr, "reload_nginx", lambda: None)
    monkeypatch.setattr(nss.db, "update_origin", lambda *a, **k: True)
    assert nss.deploy_site_route("shop.example.com", ORIGIN)
    assert calls[0][-2:] == ["tee", "/etc/nginx/conf.d/site-shop.example.com.conf"]
    assert "sh" not in calls[0] and "-c" not in calls[0]


# --- tenant DECEIVE on Mode A sites -----------------------------------------

def test_site_config_routes_418_to_the_deception_engine_when_the_key_is_set(monkeypatch):
    from services.nginx_site_service import generate_site_nginx_config
    monkeypatch.setenv("DECEPTION_INTERNAL_KEY", "k" * 32)
    conf = generate_site_nginx_config("www.example.com", {"ip": "127.0.0.1", "port": 8081})
    assert "error_page 418 = @deception;" in conf
    assert "proxy_set_header X-Internal-Deception-Key " + "k" * 32 + ";" in conf
    assert "location @deception_static" in conf


def test_site_config_leaves_deception_out_without_a_well_formed_key(monkeypatch):
    from services.nginx_site_service import generate_site_nginx_config
    for bad in ("", "short", 'x" ; return 200 "pwned', "a" * 20 + "; include /etc/passwd"):
        monkeypatch.setenv("DECEPTION_INTERNAL_KEY", bad)
        conf = generate_site_nginx_config("www.example.com", {"ip": "127.0.0.1", "port": 8081})
        assert "@deception" not in conf, bad
