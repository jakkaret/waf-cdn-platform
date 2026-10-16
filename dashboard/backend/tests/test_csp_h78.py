"""H78: the dashboard sends a Content-Security-Policy on every response."""

from fastapi.testclient import TestClient


def _client(monkeypatch, report_only=None):
    if report_only is None:
        monkeypatch.delenv("DASHBOARD_CSP_REPORT_ONLY", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_CSP_REPORT_ONLY", report_only)
    import main
    return main, TestClient(main.app)


def test_csp_enforced_by_default(monkeypatch):
    main, c = _client(monkeypatch)
    r = c.get("/api/health")
    csp = r.headers.get("content-security-policy")
    assert csp == main.CSP_POLICY
    assert "content-security-policy-report-only" not in r.headers


def test_csp_report_only_switch(monkeypatch):
    main, c = _client(monkeypatch, "1")
    r = c.get("/api/health")
    assert r.headers.get("content-security-policy-report-only") == main.CSP_POLICY
    assert "content-security-policy" not in r.headers


def test_policy_has_no_unsafe_script_sources():
    import main
    directives = dict(d.split(" ", 1) for d in main.CSP_POLICY.split("; "))
    assert directives["script-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["object-src"] == "'none'"
    assert "unsafe-eval" not in main.CSP_POLICY
