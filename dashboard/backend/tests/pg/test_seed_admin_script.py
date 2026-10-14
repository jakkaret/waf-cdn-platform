"""scripts/seed_admin.py creates the first admin without self-registration."""
import os
import stat

import pytest

from tests import pg_harness

pytestmark = [pytest.mark.pg,
              pytest.mark.skipif(not pg_harness.enabled(), reason="TEST_DATABASE_URL not set")]


@pytest.fixture(autouse=True)
def _pg(monkeypatch):
    from db import pool
    monkeypatch.setenv("DATA_BACKEND", "postgres")
    pool.close_pool()
    yield
    pool.close_pool()


def test_generate_password_creates_admin_and_never_prints_it(tmp_path, capsys):
    from scripts import seed_admin
    from services.auth_service import AuthService
    secret = tmp_path / "owner_pw"
    seed_admin.main(["--email", "Owner@Example.com", "--role", "admin", "--generate-password", str(secret)])
    out = capsys.readouterr().out
    password = secret.read_text().strip()
    assert password and password not in out
    assert stat.S_IMODE(os.stat(secret).st_mode) == 0o600
    user = AuthService().login_local("owner@example.com", password)
    assert user and user["role"] == "admin"
    # second run: unchanged, file not rewritten
    seed_admin.main(["--email", "owner@example.com", "--role", "admin", "--generate-password", str(secret)])
    assert secret.read_text().strip() == password


def test_from_env_file_and_promotion(tmp_path):
    from scripts import seed_admin
    from services.auth_service import AuthService
    env = tmp_path / "creds.env"
    env.write_text("# test\nexport VIEWER_EMAIL=v@example.com\nexport VIEWER_PASSWORD='Pa ss!1'\n")
    seed_admin.main(["--from-env", str(env), "--prefix", "VIEWER", "--role", "viewer"])
    auth = AuthService()
    assert auth.login_local("v@example.com", "Pa ss!1")["role"] == "viewer"
    seed_admin.main(["--from-env", str(env), "--prefix", "VIEWER", "--role", "admin"])
    assert auth.get_user_by_email("v@example.com")["role"] == "admin"
