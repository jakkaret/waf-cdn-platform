"""H01/H02: CI runs with a read-only token, actions are pinned by commit SHA
and the tools it installs are pinned by version."""
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
CI_TEXT = (REPO / ".github/workflows/ci.yml").read_text()
CI = yaml.safe_load(CI_TEXT)


def test_top_level_permissions_read_only():
    assert CI["permissions"] == {"contents": "read"}
    for name, job in CI["jobs"].items():
        for scope, level in (job.get("permissions") or {}).items():
            assert level == "read", f"{name}: {scope}={level}"


def test_every_action_pinned_by_sha():
    uses = re.findall(r"uses:\s*(\S+)(.*)", CI_TEXT)
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
        assert re.search(r"#\s*v\d+\.\d+\.\d+", comment), f"{ref}: add the release tag as a comment"


def test_pip_installs_pinned():
    for line in re.findall(r"run:\s*pip install (.+)", CI_TEXT):
        for tok in line.split():
            if tok.startswith("-") or tok.endswith(".txt"):
                continue
            assert "==" in tok, f"unpinned: {tok}"


def test_dependabot_watches_actions():
    cfg = yaml.safe_load((REPO / ".github/dependabot.yml").read_text())
    assert any(u["package-ecosystem"] == "github-actions" for u in cfg["updates"])
