"""H84: every file the WAF's server blocks include comes from this repo
(mounted read-only), not from whatever the image happens to ship."""
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
WAF = yaml.safe_load((REPO / "docker-compose.yml").read_text())["services"]["waf"]
DEFAULT_CONF = REPO / "nginx/templates/conf.d/default.conf.template"


def _mounted_targets():
    out = {}
    for v in WAF["volumes"]:
        parts = v.split(":")
        out[parts[1]] = (parts[0], parts[2:] == ["ro"])
    return out


def test_every_include_in_default_conf_is_mounted_from_repo():
    targets = _mounted_targets()
    includes = re.findall(r"^\s*include\s+(?:/etc/nginx/)?includes/([\w.-]+);", DEFAULT_CONF.read_text(), re.M)
    assert {"location_common.conf", "captcha_server.conf", "otp_server.conf"} <= set(includes)
    for name in set(includes):
        rendered = f"/etc/nginx/includes/{name}"
        template = f"/etc/nginx/templates/includes/{name}.template"
        src = targets.get(rendered) or targets.get(template)
        assert src, f"includes/{name} is not mounted from the repo"
        host, read_only = src
        assert (REPO / host.lstrip("./")).is_file(), host
        assert read_only, f"{host} must be mounted :ro"


def test_location_common_keeps_metrics_restricted():
    text = (REPO / "nginx/templates/includes/location_common.conf.template").read_text()
    assert "stub_status;" in text
    assert "allow ${METRICS_ALLOW_FROM};" in text and "deny ${METRICS_DENY_FROM};" in text
