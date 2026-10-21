"""DNS checks ask the domain's own nameservers first (2026-10-21: a customer
who switched a CNAME from Vercel to us waited 12 minutes because the resolver
kept the old answer). No network here: nameservers and replies are faked."""
import dns.exception
import dns.flags
import dns.message
import dns.rrset
import pytest

from services import dns_service


@pytest.fixture(autouse=True)
def authoritative_on(monkeypatch):
    monkeypatch.setenv("WAF_DNS_AUTHORITATIVE", "1")
    dns_service._ns_cache.clear()
    monkeypatch.setattr(dns_service, "_nameservers", lambda name: [("ns1.example.net", "198.51.100.1")])
    yield
    dns_service._ns_cache.clear()


def _reply(answers=(), authoritative=True):
    """Fake udp(): answers is [(name, rdtype, text)] put in the answer section."""
    def udp(query, where, timeout=None):
        reply = dns.message.make_response(query)
        if authoritative:
            reply.flags |= dns.flags.AA
        for name, rdtype, value in answers:
            reply.answer.append(dns.rrset.from_text(name, 300, "IN", rdtype, value))
        return reply
    return udp


def test_nameserver_answer_wins_over_a_stale_resolver(monkeypatch):
    monkeypatch.setattr(dns_service.dns.query, "udp",
                        _reply([("shop.example.com.", "CNAME", "waf-token-abc.cdn.local.")]))
    monkeypatch.setattr(dns_service, "_from_resolver", lambda name, rdtype: ["old.vercel-dns-017.com"])
    got = dns_service.lookup("shop.example.com", "CNAME")
    assert got == {"records": ["waf-token-abc.cdn.local"], "via": "authoritative", "nameserver": "ns1.example.net"}


def test_falls_back_to_the_resolver_when_no_nameserver_answers(monkeypatch):
    def timeout(*a, **k):
        raise dns.exception.Timeout()
    monkeypatch.setattr(dns_service.dns.query, "udp", timeout)
    monkeypatch.setattr(dns_service, "_from_resolver", lambda name, rdtype: ["cached.example.net"])
    got = dns_service.lookup("shop.example.com", "CNAME")
    assert got == {"records": ["cached.example.net"], "via": "resolver", "nameserver": ""}


def test_a_reply_without_authority_is_not_trusted(monkeypatch):
    monkeypatch.setattr(dns_service.dns.query, "udp",
                        _reply([("shop.example.com.", "CNAME", "evil.example.net.")], authoritative=False))
    monkeypatch.setattr(dns_service, "_from_resolver", lambda name, rdtype: [])
    assert dns_service.lookup("shop.example.com", "CNAME")["via"] == "resolver"


def test_switch_off_uses_only_the_resolver(monkeypatch):
    monkeypatch.setenv("WAF_DNS_AUTHORITATIVE", "0")
    called = []
    monkeypatch.setattr(dns_service.dns.query, "udp", lambda *a, **k: called.append(a))
    monkeypatch.setattr(dns_service, "_from_resolver", lambda name, rdtype: ["cached.example.net"])
    assert dns_service.lookup("shop.example.com", "CNAME")["via"] == "resolver"
    assert called == []


def test_verification_sees_a_txt_record_the_resolver_has_not_caught_up_with(monkeypatch):
    monkeypatch.setattr(dns_service.dns.query, "udp",
                        _reply([("_waf-challenge.shop.example.com.", "TXT", '"waf-token-abc"')]))
    monkeypatch.setattr(dns_service, "_from_resolver", lambda name, rdtype: [])
    assert dns_service.verify_domain_dns("shop.example.com", "waf-token-abc") is True


def test_nameservers_on_private_addresses_are_never_queried(monkeypatch):
    monkeypatch.undo()  # drop the fixture's fake _nameservers, keep it off the network below
    monkeypatch.setenv("WAF_DNS_AUTHORITATIVE", "1")
    dns_service._ns_cache.clear()

    class _NS:
        def __init__(self, t):
            self.target = t

    class _A:
        def __init__(self, ip):
            self.address = ip

    zone = dns_service.dns.name.from_text("example.com.")
    monkeypatch.setattr(dns_service.dns.resolver, "zone_for_name", lambda name, lifetime=None: zone)

    def resolve(name, rdtype, lifetime=None):
        if rdtype == "NS":
            return [_NS("ns-inside.example.com."), _NS("ns-public.example.com.")]
        return {"ns-inside.example.com": [_A("10.88.0.1"), _A("127.0.0.1")],
                "ns-public.example.com": [_A("9.9.9.9")]}[str(name).rstrip(".")]

    monkeypatch.setattr(dns_service.dns.resolver, "resolve", resolve)
    assert dns_service._nameservers("shop.example.com") == [("ns-public.example.com", "9.9.9.9")]  # documentation ranges are not global either


def test_progress_says_which_record_already_matches():
    from api.onboarding import _with_record_checks
    current = {"cname": "old.vercel-dns-017.com", "a": [], "via": "authoritative", "nameserver": "ns1.example.net",
               "txt_challenge": ["waf-token-abc"]}
    out = _with_record_checks(current, "waf-token-abc")
    assert out["txt_ok"] is True
    assert out["cname_ok"] is False
    assert "txt_challenge" not in out  # only whether it matches goes to the page
    assert _with_record_checks(current, "")["txt_ok"] is False
