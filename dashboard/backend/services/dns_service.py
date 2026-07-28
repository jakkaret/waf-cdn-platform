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

def verify_domain_dns(domain_name: str, verification_token: str) -> bool:
    """
    Checks if a domain's DNS is pointed to WAF Platform.
    Returns True if:
    1. CNAME record points to WAF_CNAME_TARGET (cdn.local)
    2. TXT record matches 'waf-verification-token=<verification_token>'
    """
    # 1. Check CNAME
    cname = resolve_cname(domain_name)
    if cname and WAF_CNAME_TARGET in cname:
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
