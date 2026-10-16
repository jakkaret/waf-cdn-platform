"""H51: ml_api never serves beyond loopback without a token, and defaults to loopback."""
import os
import subprocess
import sys

import pytest

import ml.ml_api as api

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.53"])
def test_loopback_without_token_allowed(host):
    api.check_bind_allowed(host, "")


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.77.0.2", "203.0.113.5", ""])
def test_non_loopback_without_token_refused(host):
    with pytest.raises(RuntimeError):
        api.check_bind_allowed(host, "")


@pytest.mark.parametrize("host", ["0.0.0.0", "10.77.0.2"])
def test_non_loopback_with_token_allowed(host):
    api.check_bind_allowed(host, "s3cret")


def test_host_read_from_uvicorn_argv():
    assert api.bind_host_from_argv(["uvicorn", "ml_api:app", "--host", "0.0.0.0", "--port", "5000"]) == "0.0.0.0"
    assert api.bind_host_from_argv(["uvicorn", "ml_api:app", "--host=10.77.0.2"]) == "10.77.0.2"
    assert api.bind_host_from_argv(["uvicorn", "ml_api:app"]) is None


def test_default_bind_is_loopback():
    assert api.DEFAULT_BIND == "127.0.0.1"
    assert '"0.0.0.0"' not in open(os.path.join(REPO, "ml", "ml_api.py"), encoding="utf-8").read()


def _uvicorn(host, token):
    env = {**os.environ, "PYTHONPATH": REPO, "WAF_ML_API_TOKEN": token}
    code = ("import sys, uvicorn; sys.argv=['uvicorn','ml_api:app','--host',%r,'--port','0'];"
            "uvicorn.run('ml_api:app', host=%r, port=0, lifespan='on')") % (host, host)
    return subprocess.Popen([sys.executable, "-c", code], cwd=os.path.join(REPO, "ml"), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def test_uvicorn_refuses_to_start_on_all_interfaces_without_token():
    p = _uvicorn("0.0.0.0", "")
    try:
        out, _ = p.communicate(timeout=60)
    finally:
        p.kill()
    assert p.returncode != 0
    assert "refusing to listen" in out
