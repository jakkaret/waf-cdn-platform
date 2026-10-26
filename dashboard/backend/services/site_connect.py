"""Work out how to reach a customer's site from the domain alone.

Someone who already owns a domain usually already has a site running on it,
so the domain's current DNS answer *is* the origin address. The connect flow
(api/onboarding.py) uses this module to:

1. resolve the domain as it is today (before the customer changes anything),
2. tell apart "already points at us", "behind another CDN" and "points at
   a server",
3. check from this host -- the one that will proxy to the origin -- whether
   that server answers for the domain on 443 or 80.

If it answers, the customer only has to change one DNS record: no IP to type,
nothing to install. If it does not (private address, NAT, firewall), the
flow falls back to the tunnel agent.

The probe connects to an address taken from the customer's own DNS, so it is
an SSRF and port-scan surface. It is limited on purpose: public addresses
only (origin_service.validate_ip, the same rule as origin create), ports 443
and 80 only, a short timeout, one HEAD request, no redirects followed, and
the caller rate-limits it per user.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from typing import Optional

import dns.resolver

DNS_LIFETIME_SECONDS = 3.0
PROBE_TIMEOUT_SECONDS = 3.0

# Published Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4). A
# domain that resolves here is proxied by Cloudflare, so the address is
# Cloudflare's, not the customer's server.
CLOUDFLARE_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]


def cname_target() -> str:
    return os.getenv("WAF_CNAME_TARGET", "cdn.local").strip().rstrip(".").lower()


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = DNS_LIFETIME_SECONDS
    return r


def resolve_a(name: str) -> list[str]:
    try:
        return sorted({str(r.address) for r in _resolver().resolve(name, "A")})
    except Exception:
        return []


def resolve_cname(name: str) -> str:
    try:
        for r in _resolver().resolve(name, "CNAME"):
            return str(r.target).rstrip(".").lower()
    except Exception:
        pass
    return ""


def platform_ips() -> set[str]:
    """Addresses that mean "this domain already reaches us": whatever the
    CNAME target resolves to, plus WAF_EDGE_IPS (comma-separated) for edges
    that are not in that answer."""
    from services.nginx_site_service import platform_self_ips
    ips = set(resolve_a(cname_target()))
    ips |= {str(ip) for ip in platform_self_ips()}  # includes WAF_EDGE_IPS
    return ips


def current_dns(domain: str) -> dict:
    """What the domain points at right now. The CNAME and the TXT challenge
    come from the domain's own nameservers when they answer, so a record the
    owner just changed shows here at once instead of after the resolver's
    cached copy expires. The A records still go through the resolver, which
    follows the CNAME chain. `via` says which source the CNAME came from."""
    from services import dns_service
    cname = dns_service.lookup(domain, "CNAME")
    txt = dns_service.lookup(f"_waf-challenge.{domain}", "TXT")
    return {
        "cname": (cname["records"][0] if cname["records"] else "").lower(),
        "a": resolve_a(domain),
        "via": cname["via"],
        "nameserver": cname["nameserver"],
        "txt_challenge": txt["records"],
    }


def detect_cdn(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(addr in net for net in CLOUDFLARE_NETWORKS):
        return "Cloudflare"
    return None


def _head_request(domain: str) -> bytes:
    return (
        f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: CloudWAF-OriginCheck/1.0\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def _status_from(raw: bytes) -> Optional[int]:
    line = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = line.split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return None


def probe_origin(ip: str, domain: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> dict:
    """Does `ip` answer HTTP for `domain`? Tries HTTPS (SNI = domain) first,
    then plain HTTP. Any HTTP status counts as reachable: a 403 or 500 still
    means the server is there and will get the proxied traffic.

    Refuses anything but a public address (raises ValueError) -- the caller
    must not be able to point this at the host's own network."""
    from services.nginx_site_service import direct_upstream_allowed

    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("probe target must be an IP address") from exc
    # Same rule as a direct route: public, not one of our own hosts, not the
    # QA private allowlist.
    if not direct_upstream_allowed(ip):
        raise ValueError("probe target must be a public address")

    attempts = []
    for scheme, port in (("https", 443), ("http", 80)):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                raw_sock.settimeout(timeout)
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    # Reachability only. The customer's certificate is the
                    # origin's business; the visitor-facing one is ours.
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(raw_sock, server_hostname=domain)
                else:
                    sock = raw_sock
                sock.sendall(_head_request(domain))
                status = _status_from(sock.recv(256))
            if status is not None:
                return {"reachable": True, "scheme": scheme, "port": port, "status": status}
            attempts.append(f"{scheme}: no HTTP answer")
        except (OSError, ssl.SSLError) as exc:
            attempts.append(f"{scheme}: {type(exc).__name__}")
    return {"reachable": False, "scheme": None, "port": None, "status": None, "errors": attempts}


REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _location_from(raw: bytes) -> str:
    for line in raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"location":
            return value.strip().decode("latin-1", errors="replace")
    return ""


def _forces_https(location: str, domain: str) -> bool:
    """Whether a redirect Location sends the visitor to https on the same host."""
    from urllib.parse import urlsplit
    try:
        target = urlsplit(location)
        host, port = (target.hostname or "").lower(), target.port
    except ValueError:
        return False
    return target.scheme == "https" and host == domain.lower() and port in (None, 443)


def _plain_head(ip: str, domain: str, timeout: float) -> bytes:
    """One HEAD over plain HTTP to ip:80; the answer's header block. A single
    recv() can return part of it (seen with Vercel: the status line only)."""
    with socket.create_connection((ip, 80), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(_head_request(domain))
        return _read_headers(sock)


def _read_headers(sock, limit: int = 8192) -> bytes:
    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    return raw


def direct_target(ip: str, port: int, scheme: str, domain: str,
                  timeout: float = PROBE_TIMEOUT_SECONDS) -> dict:
    """The scheme/port a direct route should use. A server that answers plain
    HTTP on :80 with a redirect to https://<same domain> (Vercel, Netlify,
    most hosts with "force HTTPS") would loop forever behind us: we fetch
    http, it sends the visitor to https, the visitor comes back to us. Such a
    target is moved to https:443 when that answers, and refused otherwise.
    Only :80 is checked (same port rule as probe_origin); an unreachable
    server is left as given -- the route is the customer's call.
    Returns {"scheme", "port", "adjusted", "status"}."""
    from services.nginx_site_service import direct_upstream_allowed

    keep = {"scheme": scheme, "port": port, "adjusted": False, "status": None}
    if scheme != "http" or port != 80 or not direct_upstream_allowed(ip):
        return keep
    try:
        raw = _plain_head(ip, domain, timeout)
    except OSError:
        return keep
    status = _status_from(raw)
    if status not in REDIRECT_STATUSES or not _forces_https(_location_from(raw), domain):
        return keep
    https = probe_origin(ip, domain, timeout=timeout)
    if https.get("reachable") and https.get("scheme") == "https":
        return {"scheme": "https", "port": 443, "adjusted": True, "status": status}
    raise ValueError(
        f"The server answers http with {status} to https://{domain}/ but does not answer https on port 443, "
        "so the site would redirect forever. Open port 443 on the server, or turn off its HTTPS redirect."
    )


def inspect_domain(domain: str) -> dict:
    """Recommend how to connect `domain`. Blocking (DNS + sockets)."""
    target = cname_target()
    dns_now = current_dns(domain)
    result = {
        "domain": domain,
        "cname_target": target,
        "current": dns_now,
        "already_points_to_platform": False,
        "cdn": None,
        "origin": None,
        "recommended_mode": "agent",
        "reason": "no_address",
    }

    ours = platform_ips()
    if dns_now["cname"] and (dns_now["cname"] == target or dns_now["cname"].endswith("." + target)):
        result["already_points_to_platform"] = True
    elif dns_now["a"] and ours and set(dns_now["a"]) <= ours:
        result["already_points_to_platform"] = True
    if result["already_points_to_platform"]:
        # The real server is no longer visible in DNS; the customer has to
        # say where it is (or use the agent).
        result["reason"] = "already_on_platform"
        return result

    for ip in dns_now["a"]:
        cdn = detect_cdn(ip)
        if cdn:
            result["cdn"] = cdn
            result["reason"] = "behind_cdn"
            return result

    for ip in dns_now["a"]:
        try:
            probe = probe_origin(ip, domain)
        except ValueError:
            result["reason"] = "private_address"
            continue
        if probe["reachable"]:
            result["origin"] = {"ip": ip, "port": probe["port"], "scheme": probe["scheme"], "status": probe["status"]}
            result["recommended_mode"] = "direct"
            result["reason"] = "reachable"
            return result
        result["reason"] = "unreachable"
    return result
