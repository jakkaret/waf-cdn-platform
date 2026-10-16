import dns.resolver
import os

WAF_CNAME_TARGET = os.getenv("WAF_CNAME_TARGET", "cdn.local")

def resolve_cname(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except Exception:
        return ""

def resolve_txt(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        results = []
        for rdata in answers:
            # Join multiple strings in a single TXT record
            txt_str = b"".join(rdata.strings).decode('utf-8')
            results.append(txt_str)
        return results
    except Exception:
        return []


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
