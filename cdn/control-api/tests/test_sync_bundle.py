"""GET /api/sync/bundle must be byte-identical while the rules are unchanged:
edges hash the bundle every few seconds and reload nginx on any difference."""
import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _load_main(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "custom-1.conf").write_text('SecRule ARGS "@contains x" "id:1,deny"\n')
    (rules / "global_blocklist.txt").write_text("203.0.113.9\n")
    monkeypatch.setenv("CONTROL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CUSTOM_RULES_DIR", str(rules))
    monkeypatch.setenv("EDGE_ALLOWED_IPS", "testclient")
    import main
    return importlib.reload(main), rules


def test_bundle_is_identical_across_calls_when_rules_do_not_change(monkeypatch, tmp_path):
    main, _ = _load_main(monkeypatch, tmp_path)
    client = TestClient(main.app)
    clock = iter([1_000_000.0, 1_000_500.0, 1_001_000.0, 1_002_000.0])
    monkeypatch.setattr(main.time, "time", lambda: next(clock))
    first = client.get("/api/sync/bundle")
    second = client.get("/api/sync/bundle")
    assert first.status_code == second.status_code == 200
    assert first.content == second.content


def test_bundle_changes_when_a_rule_changes(monkeypatch, tmp_path):
    main, rules = _load_main(monkeypatch, tmp_path)
    client = TestClient(main.app)
    before = client.get("/api/sync/bundle").content
    (rules / "custom-1.conf").write_text('SecRule ARGS "@contains y" "id:1,deny"\n')
    assert client.get("/api/sync/bundle").content != before
