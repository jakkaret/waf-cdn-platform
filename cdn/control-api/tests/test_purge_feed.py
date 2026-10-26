"""Edge cache purge: control-api serves the queue the dashboard writes
(GET /api/sync/purges, signed like the rule bundle) and the edge's rulesync
deletes the matching nginx cache files. The edge script runs here against a
stub curl, on a real directory laid out like nginx's levels=1:2 cache."""
import hashlib
import hmac
import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE.parent / "edge" / "entrypoint.d" / "99-rulesync.sh"
sys.path.insert(0, str(HERE))
KEY = "bundle-key-0123456789abcdef0123456789"


class QueueRedis:
    """The few Redis calls the purge feed makes."""

    def __init__(self):
        self.kv, self.z, self.h = {}, {}, {}

    def get(self, k):
        return self.kv.get(k)

    def zrangebyscore(self, k, lo, hi, start=0, num=None):
        items = sorted((s, m) for m, s in self.z.get(k, {}).items() if s >= lo)
        out = [m for _, m in items]
        return out[start:start + num] if num is not None else out

    def hset(self, k, field, value):
        self.h.setdefault(k, {})[field] = value

    def add(self, job_id, host, path):
        self.z.setdefault("cdn:purge:jobs", {})[f"{job_id}\t{host}\t{path}"] = job_id
        self.kv["cdn:purge:seq"] = str(job_id)


@pytest.fixture()
def feed(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTROL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CUSTOM_RULES_DIR", str(tmp_path / "rules"))
    monkeypatch.setenv("EDGE_ALLOWED_IPS", "testclient")
    monkeypatch.setenv("BUNDLE_SIGNING_KEY", KEY)
    import main
    main = importlib.reload(main)
    r = QueueRedis()
    monkeypatch.setattr(main, "shared_redis", lambda: r)
    return main, r, TestClient(main.app)


def _sig(body: bytes, key=KEY) -> str:
    return hmac.new(key.encode(), f"purge:{hashlib.sha256(body).hexdigest()}".encode(), hashlib.sha256).hexdigest()


def test_feed_lists_jobs_after_the_edges_mark_and_signs_them(feed):
    main, r, client = feed
    r.add(1, "shop.example.com", "/old")
    r.add(2, "shop.example.com", "/pricing")
    r.add(3, "shop.example.com", "/static/*")
    resp = client.get("/api/sync/purges", params={"after": 1})
    assert resp.status_code == 200
    assert resp.content == b"latest\t3\n2\tshop.example.com\t/pricing\n3\tshop.example.com\t/static/*\n"
    assert resp.headers["X-Purge-Signature"] == _sig(resp.content)
    assert r.h["cdn:purge:acks"]["testclient"].startswith("1:")


def test_feed_drops_malformed_jobs(feed):
    _, r, client = feed
    r.add(1, "shop.example.com", "/ok")
    r.z["cdn:purge:jobs"]["2\tbad host;rm\t/x"] = 2
    r.z["cdn:purge:jobs"]["3\tshop.example.com\tno-slash"] = 3
    r.z["cdn:purge:jobs"]["4\tshop.example.com\t/a b"] = 4
    r.kv["cdn:purge:seq"] = "4"
    assert client.get("/api/sync/purges").content == b"latest\t4\n1\tshop.example.com\t/ok\n"


def test_feed_is_only_for_the_edges(monkeypatch, feed):
    main, _, client = feed
    monkeypatch.setattr(main, "_EDGE_ALLOWED_IPS", {"10.88.0.2"})
    assert client.get("/api/sync/purges").status_code == 404


# ------------------------------------------------------------------ edge side

def _cache_file(cache: Path, key: str) -> Path:
    h = hashlib.md5(key.encode()).hexdigest()
    f = cache / h[-1] / h[-3:-1] / h
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(b"\x05binary-header\nKEY: " + key.encode() + b"\nHTTP/1.1 200 OK\r\n\r\nbody")
    return f


def _edge(tmp_path, body: bytes, signature=None, after=None):
    """One rulesync pass: the bundle call gets an unsigned answer (ignored),
    the purge call gets `body`."""
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    (stub / "purges").write_bytes(body)
    (stub / "purge-headers").write_text(
        f"HTTP/1.1 200 OK\r\nX-Purge-Signature: {signature or _sig(body)}\r\n\r\n")
    (stub / "bundle-headers").write_text("HTTP/1.1 200 OK\r\n\r\n")
    (stub / "bundle").write_bytes(b"")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "curl").write_text(
        "#!/bin/sh\nkind=bundle; for a in \"$@\"; do case $a in *sync/purges*) kind=purge;; esac; done\n"
        "if [ $kind = purge ]; then h=purge-headers; b=purges; else h=bundle-headers; b=bundle; fi\n"
        "echo \"$@\" >> '%s/calls'\n"
        "while [ $# -gt 0 ]; do case $1 in -D) cp '%s/'$h \"$2\"; shift;; -o) cp '%s/'$b \"$2\"; shift;; esac; shift; done\n"
        % (tmp_path, stub, stub))
    (bin_dir / "curl").chmod(0o755)
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    if after is not None:
        (state / "purge_id").write_text(str(after))
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", RULESYNC_ONCE="1",
               CUSTOM_RULES_DIR=str(tmp_path / "rules"), RULESYNC_STATE_DIR=str(state),
               EDGE_CACHE_DIR=str(tmp_path / "cache"), BUNDLE_SIGNING_KEY=KEY,
               CONTROL_API_URL="http://stub", NGINX_BIN="/bin/true")
    result = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)
    return result, state


@pytest.fixture()
def cache(tmp_path):
    c = tmp_path / "cache"
    files = {
        "page": _cache_file(c, "http|shop.example.com|GET|/pricing"),
        "page_head": _cache_file(c, "http|shop.example.com|HEAD|/pricing"),
        "pricing_more": _cache_file(c, "http|shop.example.com|GET|/pricing/plans"),
        "static": _cache_file(c, "http|shop.example.com|GET|/static/app.js"),
        "home": _cache_file(c, "http|shop.example.com|GET|/"),
        "other_site": _cache_file(c, "http|other.example.com|GET|/pricing"),
        "lookalike": _cache_file(c, "http|xshop.example.com|GET|/static/app.js"),
    }
    return files


def test_exact_path_removes_only_that_page(tmp_path, cache):
    result, state = _edge(tmp_path, b"latest\t7\n7\tshop.example.com\t/pricing\n", after=6)
    gone = {k for k, f in cache.items() if not f.exists()}
    assert gone == {"page", "page_head"}
    assert "purge #7 shop.example.com/pricing: 2 cached file(s) removed" in result.stderr
    assert (state / "purge_id").read_text().strip() == "7"
    assert "purges?after=6" in (tmp_path / "calls").read_text()


def test_prefix_and_whole_site(tmp_path, cache):
    _edge(tmp_path, b"latest\t2\n1\tshop.example.com\t/static/*\n2\tshop.example.com\t/pricing*\n")
    gone = {k for k, f in cache.items() if not f.exists()}
    assert gone == {"static", "page", "page_head", "pricing_more"}
    _edge(tmp_path, b"latest\t3\n3\tshop.example.com\t/*\n", after=2)
    left = {k for k, f in cache.items() if f.exists()}
    assert left == {"other_site", "lookalike"}


def test_bad_signature_removes_nothing(tmp_path, cache):
    result, state = _edge(tmp_path, b"latest\t9\n9\tshop.example.com\t/*\n", signature="0" * 64, after=8)
    assert all(f.exists() for f in cache.values())
    assert "purge list signature does not match" in result.stderr
    assert (state / "purge_id").read_text().strip() == "8"


def test_a_refused_line_does_not_stop_the_rest(tmp_path, cache):
    result, _ = _edge(tmp_path, b"latest\t2\n1\t../etc\t/*\n2\tshop.example.com\t/\n")
    assert "purge #1: refused" in result.stderr
    assert not cache["home"].exists() and cache["page"].exists()
