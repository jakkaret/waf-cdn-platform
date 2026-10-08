"""F-121: cached Gemini alert summaries are shared across clients/tenants, so the
prompt must be a pure function of the cache key (no client IP, country or query
string)."""
import asyncio

import services.gemini_service as gemini_mod
from services.gemini_service import GeminiService

A = {"ip": "203.0.113.10", "country": "TH", "method": "GET",
     "url": "/login?user=alice&token=SECRETQ", "rule_id": "942100",
     "attack_type": "SQL Injection", "status": "403"}


def test_prompt_fields_ignore_ip_country_and_query():
    b = dict(A, ip="198.51.100.99", country="US", url="/login?other=bob")
    assert GeminiService._attack_prompt_fields(A) == GeminiService._attack_prompt_fields(b)
    g = GeminiService()
    assert g._get_attack_signature_key(A) == g._get_attack_signature_key(b)
    assert g._get_attack_signature_key(A) != g._get_attack_signature_key(dict(A, status="429"))


def test_prompt_sent_to_gemini_has_no_ip_or_query(monkeypatch):
    sent = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "สรุป"}]}}]}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            sent["prompt"] = json["contents"][0]["parts"][0]["text"]
            return _Resp()

    monkeypatch.setattr(gemini_mod.httpx, "AsyncClient", _Client)
    asyncio.run(GeminiService().explain_attack(A))
    p = sent["prompt"]
    assert "203.0.113.10" not in p and "SECRETQ" not in p and "alice" not in p
    assert "/login" in p and "942100" in p


def test_attribution_key_includes_the_query_it_prompts_with():
    g = GeminiService()
    k1 = g._get_attribution_signature_key({"url": "/s?q=alice", "method": "GET"}, [])
    k2 = g._get_attribution_signature_key({"url": "/s?q=bob", "method": "GET"}, [])
    assert k1 != k2
