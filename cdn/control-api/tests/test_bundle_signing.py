"""P4.1 / P4.4 of the remediation plan: the rule bundle is signed and
versioned by control-api, and the edge's rulesync applies only a correctly
signed, newer bundle that passes nginx -t (restoring the previous rules when
it does not). The edge script runs here against stub curl/nginx binaries."""
import gzip
import hashlib
import hmac
import importlib
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE.parent / "edge" / "entrypoint.d" / "99-rulesync.sh"
sys.path.insert(0, str(HERE))
KEY = "bundle-key-0123456789abcdef0123456789"


def _load_main(monkeypatch, tmp_path, key=KEY):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "custom-1.conf").write_text('SecRule ARGS "@contains x" "id:1,deny"\n')
    (rules / "global_blocklist.txt").write_text("203.0.113.9\nnot-an-ip\n198.51.100.0/24\n")
    monkeypatch.setenv("CONTROL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CUSTOM_RULES_DIR", str(rules))
    monkeypatch.setenv("EDGE_ALLOWED_IPS", "testclient")
    monkeypatch.setenv("BUNDLE_SIGNING_KEY", key)
    monkeypatch.setenv("CONTROL_TOKEN", "control-token-for-tests")
    import main
    return importlib.reload(main), rules


def test_bundle_is_signed_and_versioned(monkeypatch, tmp_path):
    main, rules = _load_main(monkeypatch, tmp_path)
    client = TestClient(main.app)
    first = client.get("/api/sync/bundle")
    again = client.get("/api/sync/bundle")
    assert first.headers["X-Bundle-Version"] == again.headers["X-Bundle-Version"] == "1"
    body_sha = hashlib.sha256(first.content).hexdigest()
    expected = hmac.new(KEY.encode(), f"1:{body_sha}".encode(), hashlib.sha256).hexdigest()
    assert first.headers["X-Bundle-Signature"] == expected
    (rules / "custom-2.conf").write_text('SecRule ARGS "@contains y" "id:2,deny"\n')
    assert client.get("/api/sync/bundle").headers["X-Bundle-Version"] == "2"  # only goes up


def test_bundle_drops_malformed_blocklist_lines(monkeypatch, tmp_path):
    main, _ = _load_main(monkeypatch, tmp_path)
    body = TestClient(main.app).get("/api/sync/bundle").content
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(body))) as tar:
        names = tar.getnames()
        blocklist = tar.extractfile("global_blocklist.txt").read().decode()
    assert names.count("global_blocklist.txt") == 1
    assert blocklist.split() == ["203.0.113.9", "198.51.100.0/24"]


def test_no_signing_key_means_no_bundle(monkeypatch, tmp_path):
    main, _ = _load_main(monkeypatch, tmp_path, key="")
    assert TestClient(main.app).get("/api/sync/bundle").status_code == 503


def test_bundle_and_blocklist_only_for_the_edges(monkeypatch, tmp_path):
    monkeypatch.delenv("EDGE_ALLOWED_IPS", raising=False)
    main, _ = _load_main(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_EDGE_ALLOWED_IPS", {"10.88.0.2", "10.88.0.3"})
    for host, code in (("127.0.0.1", 404), ("172.18.0.1", 404), ("45.154.26.91", 404), ("10.88.0.2", 200)):
        client = TestClient(main.app, client=(host, 1234))
        assert client.get("/api/sync/bundle").status_code == code, host
        assert client.get("/api/blocklist").status_code == code, host


@pytest.mark.parametrize("ip", ["not-an-ip", "1.2.3.4; rm -rf /", "300.1.1.1", ""])
def test_blocklist_refuses_non_ips(monkeypatch, tmp_path, ip):
    main, _ = _load_main(monkeypatch, tmp_path)
    client = TestClient(main.app)
    resp = client.post("/api/blocklist", json={"ip": ip}, headers={"X-Control-Token": "control-token-for-tests"})
    assert resp.status_code == 400


def test_blocklist_token_compare_and_valid_ip(monkeypatch, tmp_path):
    main, _ = _load_main(monkeypatch, tmp_path)
    client = TestClient(main.app)
    assert client.post("/api/blocklist", json={"ip": "203.0.113.7"}, headers={"X-Control-Token": "wrong"}).status_code == 401
    ok = client.post("/api/blocklist", json={"ip": " 2001:DB8::1 "}, headers={"X-Control-Token": "control-token-for-tests"})
    assert ok.status_code == 200 and ok.json()["ip"] == "2001:db8::1"


# ------------------------------------------------------- edge rulesync script

def _bundle(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def _edge(tmp_path, body: bytes, version: int, key=KEY, signature=None, nginx_ok=True, current=None):
    """One rulesync pass against a stub control-api (curl) and nginx."""
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "bundle.tgz").write_bytes(body)
    sig = signature or hmac.new(key.encode(), f"{version}:{hashlib.sha256(body).hexdigest()}".encode(),
                                hashlib.sha256).hexdigest()
    (stub / "headers").write_text(f"HTTP/1.1 200 OK\r\nX-Bundle-Version: {version}\r\nX-Bundle-Signature: {sig}\r\n\r\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "curl").write_text(
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -D) cp '%s/headers' \"$2\"; shift;; -o) cp '%s/bundle.tgz' \"$2\"; shift;; esac; shift; done\n"
        % (stub, stub))
    # nginx -t fails when any rule file contains BROKEN; -s reload is recorded
    (bin_dir / "nginx").write_text(
        "#!/bin/sh\nif [ \"$1\" = -t ]; then if grep -q BROKEN %s/*.conf 2>/dev/null; then echo 'nginx: [emerg] bad rule' >&2; exit 1; fi; exit 0; fi\n"
        "echo reload >> %s/reloads\n" % (tmp_path / "rules", tmp_path))
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    rules = tmp_path / "rules"
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    if current is not None:
        (state / "version").write_text(str(current))
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", RULESYNC_ONCE="1",
               CUSTOM_RULES_DIR=str(rules), RULESYNC_STATE_DIR=str(state), NGINX_BIN=str(bin_dir / "nginx"),
               BUNDLE_SIGNING_KEY=key, CONTROL_API_URL="http://stub")
    result = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
    return result, rules, state


@pytest.fixture()
def edge_dir(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "custom-1.conf").write_text("OLD RULE\n")
    return tmp_path


def test_edge_applies_a_signed_newer_bundle(edge_dir):
    result, rules, state = _edge(edge_dir, _bundle({"custom-1.conf": "NEW RULE\n"}), 5, current=4)
    assert (rules / "custom-1.conf").read_text() == "NEW RULE\n"
    assert (state / "version").read_text().strip() == "5"
    assert "v5: updated + reloaded" in result.stderr
    assert (edge_dir / "reloads").exists()


def test_edge_refuses_a_bad_signature(edge_dir):
    result, rules, _ = _edge(edge_dir, _bundle({"custom-1.conf": "EVIL\n"}), 5, signature="0" * 64)
    assert (rules / "custom-1.conf").read_text() == "OLD RULE\n"
    assert "signature does not match" in result.stderr


def test_edge_refuses_an_older_bundle(edge_dir):
    result, rules, _ = _edge(edge_dir, _bundle({"custom-1.conf": "REPLAYED\n"}), 3, current=4)
    assert (rules / "custom-1.conf").read_text() == "OLD RULE\n"
    assert "older than the running v4" in result.stderr


def test_edge_keeps_the_previous_rules_when_nginx_refuses_the_new_ones(edge_dir):
    result, rules, state = _edge(edge_dir, _bundle({"custom-1.conf": "BROKEN\n", "custom-9.conf": "x\n"}), 6, current=5)
    assert (rules / "custom-1.conf").read_text() == "OLD RULE\n"
    assert not (rules / "custom-9.conf").exists()
    assert (state / "version").read_text().strip() == "5"
    assert "nginx -t failed, previous rules restored" in result.stderr and "bad rule" in result.stderr
    assert not (edge_dir / "reloads").exists()


def test_edge_refuses_paths_inside_the_bundle(edge_dir):
    result, rules, _ = _edge(edge_dir, _bundle({"../escape.conf": "x\n"}), 7)
    assert not (edge_dir / "escape.conf").exists()
    assert (rules / "custom-1.conf").read_text() == "OLD RULE\n"
    assert "refused entry" in result.stderr


def test_edge_without_a_key_applies_nothing(edge_dir):
    result, rules, _ = _edge(edge_dir, _bundle({"custom-1.conf": "NEW\n"}), 8, key="")
    assert (rules / "custom-1.conf").read_text() == "OLD RULE\n"
