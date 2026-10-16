"""H80: waf-nginx takes traffic straight from the internet, so it gets only
the secrets its templates use, never the whole .env through env_file."""
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
COMPOSE = yaml.safe_load((REPO / "docker-compose.yml").read_text())
WAF = COMPOSE["services"]["waf"]
ALLOWED_SECRETS = {"ML_RELAY_SECRET", "DECEPTION_INTERNAL_KEY"}
TEMPLATES = [
    "nginx/templates/conf.d/default.conf.template",
    "nginx/templates/includes/captcha_server.conf.template",
    "nginx/templates/includes/location_common.conf.template",
    "nginx/nginx.conf.template",
    *[str(p.relative_to(REPO)) for p in (REPO / "nginx/templates/modsecurity.d").glob("*.template")],
]


def test_waf_has_no_env_file():
    assert "env_file" not in WAF


def test_waf_secrets_are_exactly_the_ones_the_templates_use():
    env = WAF["environment"]
    passed = {k for k, v in env.items() if isinstance(v, str) and v.startswith("${")}
    assert passed == ALLOWED_SECRETS
    for key in ALLOWED_SECRETS:
        assert env[key].startswith("${" + key + ":?"), key  # fail fast when unset


def test_every_template_variable_reaches_the_container():
    used = set()
    for t in TEMPLATES:
        used |= set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", (REPO / t).read_text()))
    assert used <= set(WAF["environment"]), used - set(WAF["environment"])
