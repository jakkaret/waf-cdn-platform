import ipaddress
import os
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

WAF_CNAME_TARGET = os.getenv("WAF_CNAME_TARGET", "cdn.local")

# Ask the domain's own nameservers before the system resolver. The resolver
# keeps an old answer until its TTL runs out, so a customer who had pointed the
# name elsewhere (e.g. at Vercel) and then switched it to us waited up to the
# old record's TTL for verification (2026-10-21: 12 minutes, CNAME TTL 3000s).
# The authoritative answer shows the change as soon as the provider publishes it.
# WAF_DNS_AUTHORITATIVE=0 turns this off and uses only the resolver.
AUTHORITATIVE_TIMEOUT_SECONDS = 2.0
_NS_CACHE_SECONDS = 300
_ns_cache: dict = {}
_ns_lock = threading.Lock()


def _authoritative_enabled() -> bool:
    return os.getenv("WAF_DNS_AUTHORITATIVE", "1").strip() != "0"


def _nameservers(name: str) -> list:
    """[(nameserver host, ip)] for the zone holding `name`. Only public
    addresses: a zone may list a nameserver at 127.0.0.1 or 10.x, and we must
    not send packets inside our own network on a customer's say-so."""
    zone = dns.resolver.zone_for_name(name, lifetime=4.0)
    key = zone.to_text()
    now = time.monotonic()
    with _ns_lock:
        hit = _ns_cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    servers = []
    hosts = sorted(str(r.target).rstrip(".") for r in dns.resolver.resolve(zone, "NS", lifetime=4.0))
    for host in hosts[:4]:
        try:
            for a in dns.resolver.resolve(host, "A", lifetime=3.0):
                if ipaddress.ip_address(a.address).is_global:
                    servers.append((host, a.address))
        except Exception:
            continue
    with _ns_lock:
        _ns_cache[key] = (now + _NS_CACHE_SECONDS, servers)
    return servers


def _rdata_text(rdata, rdtype: str) -> str:
    if rdtype == "CNAME":
        return str(rdata.target).rstrip(".").lower()
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return rdata.to_text()


def _authoritative(name: str, rdtype: str):
    """(records, nameserver host) from the first nameserver that answers with
    authority, or None if none did (then the caller falls back)."""
    if not _authoritative_enabled():
        return None
    try:
        servers = _nameservers(name)
    except Exception:
        return None
    qname = dns.name.from_text(name)
    rt = dns.rdatatype.from_text(rdtype)
    for host, ip in servers[:3]:
        query = dns.message.make_query(qname, rt)
        query.flags &= ~dns.flags.RD
        try:
            reply = dns.query.udp(query, ip, timeout=AUTHORITATIVE_TIMEOUT_SECONDS)
            if reply.flags & dns.flags.TC:
                reply = dns.query.tcp(query, ip, timeout=AUTHORITATIVE_TIMEOUT_SECONDS)
        except Exception:
            continue
        if reply.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) or not reply.flags & dns.flags.AA:
            continue  # lame or refusing server: try the next one
        records = [_rdata_text(rd, rdtype) for rrset in reply.answer
                   if rrset.name == qname and rrset.rdtype == rt for rd in rrset]
        return records, host
    return None


def _from_resolver(name: str, rdtype: str) -> list:
    try:
        return [_rdata_text(rd, rdtype) for rd in dns.resolver.resolve(name, rdtype)]
    except Exception:
        return []


def lookup(name: str, rdtype: str) -> dict:
    """Records of one type at `name`, and where the answer came from:
    {"records": [...], "via": "authoritative" | "resolver", "nameserver": host or ""}."""
    found = _authoritative(name, rdtype)
    if found is not None:
        return {"records": found[0], "via": "authoritative", "nameserver": found[1]}
    return {"records": _from_resolver(name, rdtype), "via": "resolver", "nameserver": ""}


def resolve_cname(domain: str) -> str:
    records = lookup(domain, "CNAME")["records"]
    return records[0] if records else ""


def resolve_txt(domain: str) -> list[str]:
    return lookup(domain, "TXT")["records"]


# 2026-09-22 (self-service onboarding, overnight session): a subdomain of
# our own already-DNS-controlled wildcard needs no CNAME/TXT dance at all --
# *.waf-it-kku.online already resolves to the edge with zero setup
# (confirmed live earlier this session). Reserved labels are the ones the
# Caddyfile itself already aliases to the dashboard UI (block 1: waf-it-kku.
# online, www., main., dash.) -- letting a user "claim" one of those as
# their own origin's domain would collide with the real dashboard at that
# hostname.
OWN_WILDCARD_DOMAIN = os.getenv("WAF_OWN_WILDCARD_DOMAIN", "waf-it-kku.online").strip().lower()
_RESERVED_OWN_SUBDOMAIN_LABELS = {"www", "main", "dash"}


def is_platform_subdomain(domain_name: str) -> bool:
    """True for the platform apex itself OR any host beneath it (single- or
    multi-label). Every such host resolves to the edge with no tenant DNS setup
    and core routes an unknown Host to the tunnel router, so claiming an
    unregistered one must be restricted to the operator (see F-129). This is
    broader than is_claimable_own_wildcard_subdomain, which only covers the
    single-label auto-verify convenience."""
    d = domain_name.strip().lower().rstrip(".")  # FQDN trailing dot must not evade the check
    return d == OWN_WILDCARD_DOMAIN or d.endswith("." + OWN_WILDCARD_DOMAIN)


def is_claimable_own_wildcard_subdomain(domain_name: str) -> bool:
    d = domain_name.strip().lower()
    suffix = "." + OWN_WILDCARD_DOMAIN
    if not d.endswith(suffix) or d == OWN_WILDCARD_DOMAIN:
        return False
    label = d[: -len(suffix)]
    # Only a single-label subdomain auto-verifies -- a deeper one (e.g.
    # api.myshop.waf-it-kku.online) still goes through the normal flow,
    # since arbitrary nesting depth was never verified against the wildcard
    # cert / Caddyfile blocks the way the single-level case was.
    if not label or "." in label:
        return False
    return label not in _RESERVED_OWN_SUBDOMAIN_LABELS


def record_cname_target(verification_token: str) -> str:
    """P3.4 (N17/H41): the CNAME that proves control of one domain record.
    It carries the record's own verification token, so pointing a name at the
    platform's shared target proves nothing about who added it here.
    *.<WAF_CNAME_TARGET> resolves to the edge like the shared target does, so
    the one record still routes the traffic too."""
    target = os.getenv("WAF_CNAME_TARGET", WAF_CNAME_TARGET).strip().lower().rstrip(".")
    return f"{str(verification_token or '').strip().lower()}.{target}"


def verify_domain_dns(domain_name: str, verification_token: str) -> bool:
    """
    Checks that whoever added this domain record controls the domain's DNS.
    Returns True if:
    1. the CNAME is exactly <verification_token>.<WAF_CNAME_TARGET>
       (record_cname_target), compared without case or a trailing dot, or
    2. a TXT record (on the name or _waf-challenge.<name>) carries the token.
    A CNAME to the shared target alone no longer verifies (N17): anyone could
    point a name there, and the first account to add it got it.
    """
    if not verification_token:
        return False
    # 1. Check CNAME
    cname = resolve_cname(domain_name).strip().lower().rstrip(".")
    if cname and cname == record_cname_target(verification_token):
        print(f"[DNS Service] Domain {domain_name} verified via CNAME -> {cname}")
        return True
        
    # 2. Check TXT record
    txt_records = resolve_txt(domain_name)
    expected_txt = f"waf-verification-token={verification_token}"
    for rec in txt_records:
        if rec == expected_txt or rec == verification_token:
            print(f"[DNS Service] Domain {domain_name} verified via TXT match")
            return True
            
    # 3. Check TXT record on subdomain _waf-challenge
    challenge_domain = f"_waf-challenge.{domain_name}"
    txt_records_challenge = resolve_txt(challenge_domain)
    for rec in txt_records_challenge:
        if rec == expected_txt or rec == verification_token:
            print(f"[DNS Service] Domain {domain_name} verified via TXT challenge match")
            return True
            
    print(f"[DNS Service] Domain {domain_name} verification failed (CNAME: {cname or 'none'}, TXT records checked)")
    return False

# Quick test if run directly
if __name__ == "__main__":
    # Test resolving a known domain
    print("Testing resolve_cname for www.google.com:", resolve_cname("www.google.com"))
    print("Testing resolve_txt for google.com:", resolve_txt("google.com"))
