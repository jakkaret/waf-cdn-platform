"""An unexpanded shell command is not a JWT secret: the backend refuses it
like an empty key (Main ran on the literal "$(openssl rand -hex 32)" until
2026-10-15, a public string anyone could sign tokens with)."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]


def _import_with(secret: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "JWT_SECRET_KEY": secret}
    return subprocess.run([sys.executable, "-c", "import services.auth_service"],
                          cwd=BACKEND, env=env, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("secret", ["$(openssl rand -hex 32)", "`openssl rand -hex 32`"])
def test_unexpanded_shell_command_is_refused(secret):
    out = _import_with(secret)
    assert out.returncode != 0
    assert "unexpanded shell command" in out.stderr


def test_a_real_key_is_accepted():
    assert _import_with("9f" * 32).returncode == 0
