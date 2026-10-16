import os
import re
import ipaddress
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from services.dynamodb_service import DynamoDBService
from services.rule_manager import RuleManager, CONTAINER_NAME
from services.rbac import ARCHIVED_ORIGIN_STATUSES

logger = logging.getLogger(__name__)

db = DynamoDBService()
rule_mgr = RuleManager()

BASE_DIR = Path(__file__).resolve().parent.parent.parent
# Created on first write, not at import: importing this module (tests, the
# reconcile worker) must not create directories in the checkout.
PERSISTENT_SITES_DIR = BASE_DIR / "nginx" / "custom_sites"
CONTAINER_CONF_DIR = "/etc/nginx/conf.d"
_SITE_FILE_RE = re.compile(r"^site-(.+)\.conf$")


# Everything below is written into an nginx config file and used as a file name
# inside the nginx container, so it is validated here rather than trusted from
# the caller: a newline or ";" in a value would add nginx directives, and a "/"
# or ".." in the domain would write outside conf.d.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _safe_domain(domain_name: str) -> str:
    domain = str(domain_name or "").strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(domain):
        raise ValueError(f"invalid domain name: {domain_name!r}")
    return domain


def _safe_upstream(origin: Dict[str, Any]) -> tuple:
    ip_or_host = str(origin.get("ip", "")).strip().lower()
    try:
        ipaddress.ip_address(ip_or_host)
    except ValueError:
        if not _HOSTNAME_RE.match(ip_or_host):
            raise ValueError(f"invalid origin address: {origin.get('ip')!r}")
    try:
        port = int(origin.get("port", 80))
    except (TypeError, ValueError):
        raise ValueError(f"invalid origin port: {origin.get('port')!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid origin port: {port}")
    return ip_or_host, port


_DECEPTION_KEY_RE = re.compile(r"[A-Za-z0-9_-]{16,256}")


def _deception_locations() -> str:
    """Same @deception handling as the main server blocks in
    nginx/templates/conf.d/default.conf.template, so a tenant DECEIVE rule
    (status 418) returns the deception response instead of a bare 418. The
    template gets DECEPTION_INTERNAL_KEY from envsubst at container start;
    these files are written at runtime, so the key comes from this process's
    environment. Without a well-formed key the block is left out."""
    key = os.getenv("DECEPTION_INTERNAL_KEY", "")
    if not _DECEPTION_KEY_RE.fullmatch(key):
        return ""
    return f"""
    error_page 418 = @deception;
    location @deception {{
        rewrite ^ /api/deception/respond break;
        proxy_pass http://host.docker.internal:8000;
        proxy_connect_timeout 1s;
        proxy_read_timeout 3s;
        proxy_set_header X-Internal-Deception-Key {key};
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header X-Real-IP $waf_client_ip;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Original-Host $host;
        proxy_set_header X-Deception-Template "";
        proxy_set_header X-Matched-Rule-ID "";
        proxy_hide_header X-Deception-Engine;
        proxy_intercept_errors on;
        error_page 502 504 = @deception_static;
    }}
    location @deception_static {{
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        return 200 "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\\n";
    }}
"""


def generate_site_nginx_config(domain_name: str, origin: Dict[str, Any]) -> str:
    domain = _safe_domain(domain_name)
    ip_or_host, port = _safe_upstream(origin)

    # origin_scheme is set by the connect flow (api/onboarding.py) from what the
    # origin actually answered on; older origins have none and keep the
    # port-443 rule.
    scheme = str(origin.get("origin_scheme") or "").lower()
    is_https = scheme == "https" or (scheme != "http" and port == 443)
    # An IPv6 literal needs brackets in a URL; unbracketed, nginx reads the
    # last group as the port and `nginx -t` fails.
    try:
        url_host = f"[{ip_or_host}]" if ipaddress.ip_address(ip_or_host).version == 6 else ip_or_host
    except ValueError:
        url_host = ip_or_host

    if is_https:
        upstream_target = f"https://{url_host}" if port == 443 else f"https://{url_host}:{port}"
        # An IP origin serves this site by name (virtual host, and a
        # certificate for the visitor's domain), so it needs the visitor's
        # Host and SNI -- sending the IP made it answer with its default site
        # or fail the handshake. A hostname origin (a PaaS app such as
        # x.herokuapp.com) routes on its own name, so it keeps that.
        try:
            ipaddress.ip_address(ip_or_host)
            upstream_name = "$host"
        except ValueError:
            upstream_name = ip_or_host
        host_header = upstream_name
        ssl_directives = f"""        proxy_ssl_server_name on;
        proxy_ssl_name {upstream_name};
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_set_header X-Forwarded-Proto https;"""
    else:
        upstream_target = f"http://{url_host}:{port}"
        host_header = "$host"
        ssl_directives = """        proxy_set_header X-Forwarded-Proto $scheme;"""

    # No timestamp in the file: reconcile_site_routes() compares the text with
    # what is in the container, so the same input must give the same bytes.
    config = f"""# Managed Dynamic Site: {domain} -> {upstream_target}
# Generated by CloudWAF Auto-Routing Engine

server {{
    listen 8080;
    server_name {domain};

    access_log /var/log/nginx/access.json json_combined;
    error_log /var/log/nginx/error.log warn;
    include /etc/nginx/includes/captcha_server.conf;
    include /etc/nginx/includes/otp_server.conf;

    modsecurity on;
    modsecurity_transaction_id "$request_id";

    # Static-looking paths go through the shield too (P2.1, H85); the rate
    # limiter in control-api skips real static assets on its own.
    location ~* \\.(?:css|js|jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|json|map)$ {{
        auth_request /internal-shield-check;
        auth_request_set $retry_after $upstream_http_retry_after;
        auth_request_set $shield_type $upstream_http_x_shield_type;
        auth_request_set $shield_protected $upstream_http_x_shield_protected;
        more_set_headers "Cache-Control: $waf_cache_control";

        proxy_pass {upstream_target};
        proxy_set_header Host {host_header};
{ssl_directives}
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header X-Real-IP $waf_client_ip;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }}

    location / {{
        mirror /internal-ml-capture;
        mirror_request_body on;

        auth_request /internal-shield-check;
        auth_request_set $retry_after $upstream_http_retry_after;
        auth_request_set $shield_type $upstream_http_x_shield_type;
        auth_request_set $shield_protected $upstream_http_x_shield_protected;
        more_set_headers "Cache-Control: $waf_cache_control";

        proxy_pass {upstream_target};
        proxy_set_header Host {host_header};
{ssl_directives}
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header X-Real-IP $waf_client_ip;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_redirect off;
        proxy_buffering off;
    }}

{_deception_locations()}
    error_page 403 /403.html;
    location = /403.html {{ root /usr/share/nginx/html; internal; }}
}}
"""
    return config


def deploy_site_route(domain_name: str, origin: Dict[str, Any]) -> bool:
    """Write one site file by hand (scripts/qa/seed.py only; the app uses
    reconcile_site_routes). P3.8 (H38): the origin address is checked like
    any other -- a public address, or one ORIGIN_ALLOW_PRIVATE_CIDRS allows."""
    domain = _safe_domain(domain_name)
    from services.origin_service import validate_ip
    if not validate_ip(str(origin.get("ip", ""))):
        raise ValueError(f"origin address {origin.get('ip')!r} is not allowed")
    filename = f"site-{domain}.conf"
    config_content = generate_site_nginx_config(domain, origin)

    # 1. Write persistent copy on host
    PERSISTENT_SITES_DIR.mkdir(parents=True, exist_ok=True)
    host_file = PERSISTENT_SITES_DIR / filename
    host_file.write_text(config_content, encoding="utf-8")

    # 2. Write into nginx container /etc/nginx/conf.d/
    container_path = f"/etc/nginx/conf.d/{filename}"
    # tee with an argument list -- no shell, so the path is never interpreted.
    write_cmd = ["docker", "exec", "-i", CONTAINER_NAME, "tee", container_path]
    res = subprocess.run(write_cmd, input=config_content.encode("utf-8"), capture_output=True)
    if res.returncode != 0:
        logger.error(f"Failed to write config into nginx container: {res.stderr.decode()}")
        return False

    # 3. Test nginx config (Safety Net!)
    try:
        rule_mgr.test_nginx()
    except Exception as e:
        logger.error(f"Nginx test failed for site {domain}, rolling back: {e}")
        subprocess.run(["docker", "exec", CONTAINER_NAME, "rm", "-f", container_path], capture_output=True)
        if host_file.exists():
            host_file.unlink()
        raise RuntimeError(f"Nginx configuration test failed: {e}")

    # 4. Reload nginx (Zero Downtime)
    try:
        rule_mgr.reload_nginx()
        logger.info(f"Successfully deployed and reloaded route for {domain}")
    except Exception as e:
        logger.error(f"Failed to reload nginx for site {domain}: {e}")
        return False

    # 5. Activate Origin in DynamoDB if currently pending
    origin_id = origin.get("id")
    if origin_id:
        now = datetime.now().isoformat() + "Z"
        db.update_origin(origin_id, {"status": "active", "updated_at": now})
        logger.info(f"Origin {origin_id} marked as ACTIVE")

    return True


def remove_site_route(domain_name: str) -> bool:
    domain = _safe_domain(domain_name)
    filename = f"site-{domain}.conf"
    host_file = PERSISTENT_SITES_DIR / filename
    if host_file.exists():
        host_file.unlink()

    container_path = f"/etc/nginx/conf.d/{filename}"
    subprocess.run(["docker", "exec", CONTAINER_NAME, "rm", "-f", container_path], capture_output=True)

    try:
        rule_mgr.test_nginx()
        rule_mgr.reload_nginx()
        logger.info(f"Removed route for {domain}")
        return True
    except Exception as e:
        logger.error(f"Failed to reload nginx after removing {domain}: {e}")
        return False


# --- Direct-mode routes: desired state from the database ------------------
#
# deploy_site_route() above was never called by the app (only by
# scripts/qa/seed.py), so a verified domain on an origin reached by IP got no
# server block and fell through to the tunnel router ("no route found"). And
# files written with `docker exec tee` live only in the container's writable
# layer: recreating waf-nginx (e.g. the CRS image pin on 2026-10-03) drops them.
# reconcile_site_routes() fixes both. It rebuilds the set of site files from
# the database and makes the container match, so it is safe to run on a timer
# and right after a domain changes.
#
# Only origins with connection_mode == "direct" are managed, and only files
# this code wrote are ever changed or removed: each one starts with
# MANAGED_MARKER. Hand-placed files and scripts/qa/seed.py's routes have no
# marker and are left alone, whatever the database says.

MANAGED_MARKER = "# managed-by: site-reconcile"

_reconcile_lock = threading.Lock()
# Domains whose site file the last reconcile confirmed in the container;
# GET /api/onboarding/progress reads it to report "route active".
_deployed_domains: set = set()
# domain -> why its file was refused (nginx -t output or docker error).
_failed_domains: Dict[str, str] = {}
# Restores that failed (docker error mid-rollback): domain -> text to put
# back (None = remove). Retried first on the next run.
_pending_restores: Dict[str, Optional[str]] = {}
# A reload that nginx refused or that errored; retried on the next run even if
# nothing else changed, so applied files are not left unloaded.
_reload_pending = False
# Domains whose file was written but has not been through a successful reload
# yet. Not reported live until one succeeds, however many runs that takes.
_unreloaded: set = set()



def deployed_direct_domains() -> set:
    return set(_deployed_domains)


def failed_direct_domains() -> Dict[str, str]:
    return dict(_failed_domains)


def direct_upstream_allowed(address: str) -> bool:
    """A direct-mode origin must be a public IP literal. A hostname would be
    resolved by nginx at reload time, so a name that is fine when checked can
    later resolve to 127.0.0.1 or host.docker.internal and send tenant
    traffic into the WAF host's own services (SSRF)."""
    from services.origin_service import validate_ip
    try:
        addr = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return False
    # The platform's own hosts are public addresses too. Proxying to one of
    # them lets a tenant reach ports that are only open to the WAF's own
    # containers (traffic to the host's own IP keeps the container source
    # address). Compared as parsed addresses so ::ffff:a.b.c.d can't slip by.
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if addr in platform_self_ips():
        return False
    # validate_ip lets ORIGIN_ALLOW_PRIVATE_CIDRS through (qa-echo on waf-net
    # for the integration suite); a tenant's direct route must not reach it.
    from services.origin_service import _ALLOWED_PRIVATE_NETS
    if any(addr in net for net in _ALLOWED_PRIVATE_NETS):
        return False
    return validate_ip(str(address).strip())


# Main and the edges -- the same hosts as api/cdn.py REGIONS_META. Override
# with WAF_SELF_IPS; WAF_EDGE_IPS (also used by services/site_connect.py) adds to it.
DEFAULT_SELF_IPS = "178.104.53.123,45.154.26.91,57.158.25.236"


def platform_self_ips() -> set:
    raw = os.getenv("WAF_SELF_IPS", DEFAULT_SELF_IPS) + "," + os.getenv("WAF_EDGE_IPS", "")
    out = set()
    for part in raw.split(","):
        try:
            out.add(ipaddress.ip_address(part.strip()))
        except ValueError:
            continue
    return out


def desired_direct_sites(domains: list, origins: list) -> Dict[str, str]:
    """domain -> config text for every verified domain whose origin is direct
    mode, active and a public IP. A row that fails validation is skipped, not
    fatal."""
    origins_by_id = {str(o.get("id")): o for o in origins}
    desired: Dict[str, str] = {}
    for d in domains:
        if not d.get("dns_verified"):
            continue
        origin = origins_by_id.get(str(d.get("origin_id")))
        if not origin or origin.get("connection_mode") != "direct":
            continue
        if origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
            continue
        if not direct_upstream_allowed(origin.get("ip", "")):
            logger.warning("site route skipped for %r: origin address %r is not a public IP",
                           d.get("domain_name"), origin.get("ip"))
            continue
        try:
            domain = _safe_domain(d.get("domain_name", ""))
            desired[domain] = MANAGED_MARKER + "\n" + generate_site_nginx_config(domain, origin)
        except ValueError as exc:
            logger.warning("site route skipped for %r: %s", d.get("domain_name"), exc)
    return desired


def _docker(args: list, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", *(["-i"] if input_text is not None else []), CONTAINER_NAME, *args],
        input=input_text.encode("utf-8") if input_text is not None else None,
        capture_output=True,
        timeout=20,
    )


def _container_site_files() -> Dict[str, str]:
    """domain -> current text of each site-<domain>.conf in the container,
    read with one `tar` instead of one `cat` per file."""
    import io
    import tarfile
    res = _docker(["tar", "-cf", "-", "-C", CONTAINER_CONF_DIR, "."])
    if res.returncode != 0:
        raise RuntimeError(f"cannot read {CONTAINER_CONF_DIR}: {res.stderr.decode(errors='replace')[:200]}")
    files: Dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(res.stdout)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            m = _SITE_FILE_RE.match(member.name.rsplit("/", 1)[-1])
            if not m:
                continue
            try:
                domain = _safe_domain(m.group(1))
            except ValueError:
                continue
            files[domain] = tar.extractfile(member).read().decode(errors="replace")
    return files


def _write_site(domain: str, text: str) -> None:
    res = _docker(["tee", f"{CONTAINER_CONF_DIR}/site-{domain}.conf"], input_text=text)
    if res.returncode != 0:
        raise RuntimeError(f"write site-{domain}.conf failed: {res.stderr.decode(errors='replace')[:200]}")
    try:
        PERSISTENT_SITES_DIR.mkdir(parents=True, exist_ok=True)
        (PERSISTENT_SITES_DIR / f"site-{domain}.conf").write_text(text, encoding="utf-8")
    except OSError as exc:  # the host copy is informational only
        logger.warning("host copy of site-%s.conf not written: %s", domain, exc)


def _remove_site(domain: str) -> None:
    res = _docker(["rm", "-f", f"{CONTAINER_CONF_DIR}/site-{domain}.conf"])
    if res.returncode != 0:
        raise RuntimeError(f"remove site-{domain}.conf failed: {res.stderr.decode(errors='replace')[:200]}")
    try:
        (PERSISTENT_SITES_DIR / f"site-{domain}.conf").unlink(missing_ok=True)
    except OSError:
        pass


def _restore(domain: str, previous: Optional[str]) -> None:
    """Put one file back as it was. Logs instead of raising, so one failed
    restore never stops the rest or hides the original error; a failed one
    is queued and retried at the start of the next run."""
    try:
        if previous is None:
            _remove_site(domain)
        else:
            _write_site(domain, previous)
        _pending_restores.pop(domain, None)
    except Exception as exc:
        _pending_restores[domain] = previous
        logger.error("site reconcile: could not restore site-%s.conf (will retry): %s", domain, exc)


def reconcile_site_routes() -> Dict[str, Any]:
    """Make the container's direct-mode site files match the database.

    Each change is applied on its own and checked with `nginx -t`; a change
    nginx refuses is undone and reported in "failed", and the rest still go
    through, so one tenant's bad origin cannot hold up everyone else's routes.
    nginx is reloaded once at the end if anything changed.
    Blocking (DynamoDB scans, docker exec): call it from a worker thread."""
    global _deployed_domains, _failed_domains, _reload_pending, _unreloaded
    with _reconcile_lock:
        for domain, previous in list(_pending_restores.items()):
            _restore(domain, previous)
        domains = db.list_domains()
        origins = db.list_origins()
        desired = desired_direct_sites(domains, origins)

        current = _container_site_files()
        failed: Dict[str, str] = {}
        to_write = {}
        for d, t in desired.items():
            if current.get(d) == t:
                continue
            if d in current and MANAGED_MARKER not in current[d]:
                # A hand-placed or seed.py route already serves this name;
                # never overwrite a file this code did not write.
                failed[d] = "a site file not written by reconcile already exists for this domain"
                continue
            to_write[d] = t
        to_remove = [d for d, text in current.items() if d not in desired and MANAGED_MARKER in text]
        if to_remove and not domains:
            # An empty domains table next to live site files is far more
            # likely a read problem than a real "delete everything".
            logger.warning("site reconcile: no domain rows, keeping %d site file(s)", len(to_remove))
            to_remove = []

        if to_write or to_remove:
            # If conf.d is already broken (a failed restore, another writer's
            # bad file), every per-file test below would fail and blame each
            # tenant in turn. Check first and change nothing.
            try:
                rule_mgr.test_nginx()
            except Exception as exc:
                logger.error("site reconcile: nginx config already invalid, changing nothing: %s", exc)
                return {"added": [], "updated": [], "removed": [], "failed": sorted(failed),
                        "baseline_error": str(exc)[:300]}

        applied: list = []
        for domain, text in to_write.items():
            try:
                _write_site(domain, text)
                rule_mgr.test_nginx()
                applied.append(domain)
            except Exception as exc:
                failed[domain] = str(exc)[:300]
                logger.error("site reconcile: site-%s.conf refused, keeping the previous state: %s", domain, exc)
                _restore(domain, current.get(domain))
        removed: list = []
        for domain in to_remove:
            try:
                _remove_site(domain)
                rule_mgr.test_nginx()
                removed.append(domain)
            except Exception as exc:
                failed[domain] = str(exc)[:300]
                logger.error("site reconcile: removing site-%s.conf failed: %s", domain, exc)
                _restore(domain, current[domain])

        _unreloaded |= set(applied)
        reload_error = None
        if applied or removed or _reload_pending:
            try:
                rule_mgr.reload_nginx()  # runs `nginx -t` once more first (F-037)
                _reload_pending = False
                _unreloaded = set()
            except Exception as exc:
                # nginx keeps serving its previous config; report, don't raise,
                # and try the reload again next run.
                _reload_pending = True
                reload_error = str(exc)[:300]
                logger.error("site reconcile: nginx reload refused, will retry: %s", exc)

        _failed_domains = failed
        # A file is live only after a reload that included it succeeded --
        # in this run or a later retry, not merely because it is on disk.
        _deployed_domains = {d for d in desired if d not in failed} - _unreloaded
        origins_by_id = {str(o.get("id")): o for o in origins}
        now = datetime.now().isoformat() + "Z"
        for d in domains:
            origin = origins_by_id.get(str(d.get("origin_id")))
            try:
                name = _safe_domain(d.get("domain_name", ""))
            except ValueError:
                continue
            if name in _deployed_domains and origin and origin.get("status") == "pending":
                db.update_origin(origin["id"], {"status": "active", "updated_at": now})
                origin["status"] = "active"

        summary = {
            "added": sorted(d for d in applied if d not in current),
            "updated": sorted(d for d in applied if d in current),
            "removed": sorted(removed),
            "failed": sorted(failed),
        }
        if reload_error:
            summary["reload_error"] = reload_error
        if applied or removed or failed or reload_error:
            logger.info("site reconcile: %s", summary)
        return summary


async def site_route_worker(interval_seconds: int = 120) -> None:
    """Re-applies the site files on a timer, so a recreated waf-nginx gets
    them back within one interval without a manual step."""
    import asyncio
    while True:
        try:
            await asyncio.to_thread(reconcile_site_routes)
        except Exception as exc:
            logger.error("site route worker: %s", exc)
        await asyncio.sleep(interval_seconds)