"""Regression test for F-017: the SPA catch-all must not serve files from
outside the built frontend directory. A dot-segment path (percent-encoded so
the HTTP client does not normalise it away) must never return an out-of-tree
file such as the backend source."""


def _leaks(resp) -> bool:
    # A sentinel only present in the backend source file we try to escape to.
    return "def serve_react_app" in resp.text


def test_catchall_rejects_encoded_dot_segment_traversal(client):
    # These resolve, pre-fix, to dashboard/backend/main.py (an existing file
    # outside frontend/dist), which the old handler happily served.
    for path in (
        "/%2e%2e/%2e%2e/main.py",
        "/%2e%2e/%2e%2e/backend/main.py",
        "/..%2f..%2fmain.py",
    ):
        resp = client.get(path)
        assert not _leaks(resp), f"path traversal leaked a file for {path!r}"


def test_catchall_still_allows_api_404_and_spa_fallback(client):
    # api/* still 404s, and an ordinary unknown route still falls back without
    # leaking anything.
    assert client.get("/api/definitely-not-a-route").status_code == 404
    assert not _leaks(client.get("/some/spa/route"))
