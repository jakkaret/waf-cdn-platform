"""H53: the Gemini API key travels in the x-goog-api-key header, never in the URL."""
import asyncio
import logging
import pathlib

import httpx
import pytest

import services.gemini_service as gs

BACKEND = pathlib.Path(__file__).resolve().parents[1]


class _Recorder:
    def __init__(self):
        self.calls = []

    def install(self, monkeypatch):
        rec = self

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, json=None, headers=None, **kw):
                rec.calls.append((str(url), dict(headers or {})))
                return httpx.Response(500, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx, "AsyncClient", FakeClient)


def test_no_key_query_string_in_source():
    for path in list((BACKEND / "services").glob("*.py")) + list((BACKEND / "api").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "?key=" not in text, f"{path.name} still builds a ?key= URL"


CALLS = {
    "explain_attack": lambda s: s.explain_attack({"uri": "/x", "method": "GET", "rule_id": "942100", "attack_type": "SQLi"}),
    "explain_attribution": lambda s: s.explain_attribution({"url": "/x", "method": "GET"}, [{"feature": "keyword_matches", "value": 1, "contribution": 0.3}]),
    "parse_natural_time_range": lambda s: s.parse_natural_time_range("last hour"),
    "generate_range_summary": lambda s: s.generate_range_summary("last hour", {"total": 1}),
    "generate_postmortem_narrative": lambda s: s.generate_postmortem_narrative({"events": []}),
    "draft_cve_rule_pattern": lambda s: s.draft_cve_rule_pattern("CVE-2026-0001", "test", "tag"),
}


@pytest.mark.parametrize("name", sorted(CALLS))
def test_gemini_service_sends_key_in_header(monkeypatch, name):
    rec = _Recorder()
    rec.install(monkeypatch)
    svc = gs.GeminiService()
    svc.api_key = "test-key-123"
    asyncio.run(CALLS[name](svc))
    assert rec.calls, f"{name} made no Gemini call"
    for url, headers in rec.calls:
        assert "key=" not in url
        assert "test-key-123" not in url
        assert headers.get("x-goog-api-key") == "test-key-123"


def test_copilot_uses_header_helper():
    text = (BACKEND / "api" / "copilot.py").read_text(encoding="utf-8")
    assert "headers=gemini_headers(api_key)" in text
    assert "?key=" not in text


def test_httpx_loggers_quiet():
    import main  # noqa: F401  (sets the levels at import)

    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
