"""F-037 regression: every nginx reload is preceded by `nginx -t`; an invalid
config is never reloaded and is surfaced (settings roll back, IP rules report
nginx_applied=False) instead of being swallowed."""
import json

import pytest

import services.settings_service as settings_mod
from services.rule_manager import NginxConfigError, RuleManager

EMERG = 'Docker command failed: nginx: [emerg] duplicate rule id 1000001\nnginx: configuration file test failed'


def _rm_with(calls, fail_test_with=None):
    rm = RuleManager.__new__(RuleManager)  # no rules-dir side effects needed

    def fake_exec(args):
        calls.append(args)
        if args == ("nginx", "-t") and fail_test_with:
            raise RuntimeError(fail_test_with)

    rm._run_docker_exec = fake_exec
    return rm


def test_reload_runs_config_test_first():
    calls = []
    _rm_with(calls).reload_nginx()
    assert calls == [("nginx", "-t"), ("nginx", "-s", "reload")]


def test_invalid_config_is_never_reloaded():
    calls = []
    with pytest.raises(NginxConfigError):
        _rm_with(calls, EMERG).reload_nginx()
    assert ("nginx", "-s", "reload") not in calls


def test_unreachable_nginx_is_not_reported_as_bad_config():
    calls = []
    with pytest.raises(RuntimeError) as e:
        _rm_with(calls, "Docker command failed: No such container: waf-nginx").reload_nginx()
    assert not isinstance(e.value, NginxConfigError)
    assert ("nginx", "-s", "reload") not in calls


@pytest.fixture
def svc(tmp_path, monkeypatch):
    override = tmp_path / "00-modsecurity-override.conf"
    override.write_text("# previous live override\n", encoding="utf-8")
    monkeypatch.setattr(settings_mod, "OVERRIDE_FILE", override)
    s = settings_mod.SettingsService()
    monkeypatch.setattr(s, "_sync_ml_policy", lambda *a, **k: None)
    return s, override


def test_rejected_override_rolls_back_and_persists_nothing(svc, monkeypatch):
    s, override = svc
    before = settings_mod.SETTINGS_FILE.read_text(encoding="utf-8") if settings_mod.SETTINGS_FILE.exists() else None

    def reject():
        raise NginxConfigError(EMERG)

    monkeypatch.setattr(s.rule_manager, "reload_nginx", reject)
    with pytest.raises(NginxConfigError):
        s.update_settings({"waf_mode": "DetectionOnly"})
    assert override.read_text(encoding="utf-8") == "# previous live override\n"
    after = settings_mod.SETTINGS_FILE.read_text(encoding="utf-8") if settings_mod.SETTINGS_FILE.exists() else None
    assert after == before


def test_unreachable_nginx_still_saves_settings(svc, monkeypatch):
    s, _ = svc

    def unreachable():
        raise RuntimeError("Docker command failed: Cannot connect to the Docker daemon")

    monkeypatch.setattr(s.rule_manager, "reload_nginx", unreachable)
    s.update_settings({"waf_mode": "DetectionOnly"})
    saved = json.loads(settings_mod.SETTINGS_FILE.read_text(encoding="utf-8"))
    assert saved["waf_mode"] == "DetectionOnly"


def test_ip_rule_reports_not_applied_on_bad_config(tmp_path, monkeypatch):
    import services.ip_rule_service as ip_rules

    for name in ("BLOCKLIST_TXT", "WHITELIST_TXT", "BLOCKLIST_CONF", "WHITELIST_CONF"):
        monkeypatch.setattr(ip_rules, name, tmp_path / getattr(ip_rules, name).name)
    svc = ip_rules.IPRuleService()

    def reject():
        raise NginxConfigError(EMERG)

    monkeypatch.setattr(svc.rule_manager, "reload_nginx", reject)
    res = svc.add_rule("203.0.113.77", rule_type="block")
    assert res["nginx_applied"] is False
