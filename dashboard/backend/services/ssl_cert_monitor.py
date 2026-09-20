"""SSL certificate status monitor.

Populates `waf_ssl_certs` (previously a DynamoDBService table reference with
zero read/write callers anywhere in the codebase -- confirmed empty) with
real, live-probed certificate status per domain, and sends a Telegram
warning before a certificate expires.

Design note (2026-09-21): this probes each domain's public HTTPS endpoint
directly -- the same way a real client (curl, a browser) reaches it -- and
never reads any single node's local Caddy certificate store. Main's own
Caddy container was found mid-investigation to have been failing ACME
issuance for some of these exact domains for ~2.4 days (ACME's HTTP-01/
TLS-ALPN-01 validation traffic lands on the edge node, not on Main, so
Main's own on-demand/auto-HTTPS manager can never complete it there), while
those same domains already serve a valid, non-expiring-soon certificate to
real traffic via the edge. Reading Main's local cert store would have
reported those domains as MISSING while users get a valid cert -- the exact
fabricated-data bug class this feature exists to remove, just inverted.
"""
import asyncio
import datetime as dt
import os
import socket
import ssl
from typing import Callable, Optional

import httpx

CERT_EXPIRY_ALERT_THRESHOLD_DAYS = int(os.getenv("SSL_CERT_ALERT_THRESHOLD_DAYS", "14"))
CERT_REALERT_COOLDOWN_HOURS = int(os.getenv("SSL_CERT_REALERT_COOLDOWN_HOURS", "24"))
CERT_CHECK_INTERVAL_SECONDS = int(os.getenv("SSL_CERT_CHECK_INTERVAL_SECONDS", str(6 * 3600)))


def parse_not_after(not_after: str) -> dt.datetime:
    """Parses the exact string shape ssl.SSLSocket.getpeercert()['notAfter']
    returns, e.g. "Nov 22 14:07:01 2026 GMT" -- confirmed live against
    juice.waf-it-kku.online this session. Per RFC 5280, X.509 validity
    timestamps are always UTC, which Python's ssl module always renders as
    the literal suffix "GMT" (not parsed by %Z reliably across platforms,
    so stripped and attached explicitly instead)."""
    cleaned = not_after.strip()
    if cleaned.endswith("GMT"):
        cleaned = cleaned[: -len("GMT")].strip()
    parsed = dt.datetime.strptime(cleaned, "%b %d %H:%M:%S %Y")
    return parsed.replace(tzinfo=dt.timezone.utc)


def compute_days_remaining(not_after: dt.datetime, now: dt.datetime) -> int:
    """Floors to whole days -- a cert with 5 days 1 hour left must read as
    5, not 6 (rounding up would report a cert as safe a day later than it
    actually is)."""
    return (not_after - now).days


def should_alert(
    days_remaining: int,
    last_alerted_at: Optional[dt.datetime],
    now: dt.datetime,
    threshold_days: int = CERT_EXPIRY_ALERT_THRESHOLD_DAYS,
    cooldown_hours: int = CERT_REALERT_COOLDOWN_HOURS,
) -> bool:
    if days_remaining > threshold_days:
        return False
    # An already-expired cert is a strictly worse state than "expiring
    # soon" -- never let the re-alert cooldown suppress it.
    if days_remaining < 0:
        return True
    if last_alerted_at is None:
        return True
    return (now - last_alerted_at) >= dt.timedelta(hours=cooldown_hours)


def _issuer_label(cert: dict) -> str:
    issuer = cert.get("issuer") or ()
    flat = {k: v for rdn in issuer for k, v in rdn}
    return flat.get("organizationName") or flat.get("commonName") or "unknown"


def probe_certificate(domain: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Real TLS handshake against `domain:port` with SNI=domain, validated
    against the default trust store (catches broken chains / expired roots
    / hostname mismatches -- real failure modes a real client would also
    hit, not just raw expiry). Never raises: any failure degrades to a
    structured {"status": "error", ...} so one unreachable domain can't take
    down a whole scan."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
        return {
            "status": "ok",
            "not_after": parse_not_after(cert["notAfter"]).isoformat(),
            "issuer": _issuer_label(cert),
        }
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}


async def _probe_certificate_async(domain: str) -> dict:
    return await asyncio.to_thread(probe_certificate, domain)


async def _send_expiry_telegram_alert(domain: str, days_remaining: int, not_after: str) -> None:
    from services.settings_service import SettingsService

    settings = SettingsService().get_settings()
    bot_token = settings.get("telegram_bot_token")
    chat_id = settings.get("telegram_chat_id")
    if not bot_token or not chat_id:
        return

    state = "EXPIRED" if days_remaining < 0 else f"expires in {days_remaining} day(s)"
    msg = (
        "\U0001F512 *SSL Certificate Warning*\n\n"
        f"Domain: `{domain}`\n"
        f"Status: {state} (notAfter: {not_after})\n"
        "Action: check ACME renewal is completing for this domain."
    )
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"},
            )
    except Exception as e:
        print(f"[SSL Cert Monitor] Failed to send Telegram alert for {domain}: {e}")


def _persist_cert_record(db, record: dict) -> None:
    # waf_ssl_certs' real DynamoDB key schema (pre-existing, from before this
    # table had any callers) is HASH="id", with a domain_id-index GSI for a
    # foreign key into domains_table -- a fit for the "bring your own
    # domain" flow only. Tunnel-claimed domains (cloudwaf/FRP) have no
    # domains_table row at all, so this monitor keys directly on the domain
    # string as `id` instead of trying to resolve a domains_table.id for
    # every domain -- confirmed live 2026-09-21 (describe_table) rather than
    # assumed.
    record_id = record["domain"]
    existing = db.ssl_certs_table.get_item(Key={"id": record_id}).get("Item")
    if existing is None:
        db.ssl_certs_table.put_item(Item={**record, "id": record_id})
        return
    # 2026-09-21: caught live -- "status" is a DynamoDB reserved keyword,
    # so a bare `status = :v` UpdateExpression fails against the real table
    # (the fake used in tests doesn't validate reserved words, so no test
    # caught this; only surfaced once a second scan cycle hit the
    # update_item path against real AWS). Every field now goes through an
    # ExpressionAttributeNames placeholder rather than relying on knowing
    # which field names happen to collide.
    names = {}
    values = {}
    set_clauses = []
    for i, (k, v) in enumerate(record.items()):
        if k == "domain":
            continue
        name_token = f"#f{i}"
        val_token = f":v{i}"
        names[name_token] = k
        values[val_token] = v
        set_clauses.append(f"{name_token} = {val_token}")
    db.ssl_certs_table.update_item(
        Key={"id": record_id},
        UpdateExpression="SET " + ", ".join(set_clauses),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


async def check_domain_certificate(
    domain: str,
    db,
    now: Optional[dt.datetime] = None,
    probe: Optional[Callable] = None,
    send_alert: Optional[Callable] = None,
    threshold_days: int = CERT_EXPIRY_ALERT_THRESHOLD_DAYS,
    cooldown_hours: int = CERT_REALERT_COOLDOWN_HOURS,
) -> dict:
    """Probes one domain, persists its real status to waf_ssl_certs, and
    sends (at most once per cooldown window) a Telegram warning once it
    crosses the expiry threshold. Returns the persisted record."""
    now = now or dt.datetime.now(dt.timezone.utc)
    probe = probe or _probe_certificate_async
    send_alert = send_alert or _send_expiry_telegram_alert

    result = await probe(domain)
    existing = db.ssl_certs_table.get_item(Key={"id": domain}).get("Item") or {}
    last_alerted_at = None
    if existing.get("last_alerted_at"):
        last_alerted_at = dt.datetime.fromisoformat(existing["last_alerted_at"])

    record = {"domain": domain, "status": result["status"], "checked_at": now.isoformat()}

    if result["status"] == "ok":
        not_after = dt.datetime.fromisoformat(result["not_after"])
        days_remaining = compute_days_remaining(not_after, now)
        record["not_after"] = result["not_after"]
        record["issuer"] = result.get("issuer")
        record["days_remaining"] = days_remaining

        if should_alert(days_remaining, last_alerted_at, now, threshold_days, cooldown_hours):
            await send_alert(domain, days_remaining, result["not_after"])
            record["last_alerted_at"] = now.isoformat()
        elif existing.get("last_alerted_at"):
            record["last_alerted_at"] = existing["last_alerted_at"]
    else:
        record["days_remaining"] = None
        record["error"] = result.get("error")
        if existing.get("last_alerted_at"):
            record["last_alerted_at"] = existing["last_alerted_at"]

    _persist_cert_record(db, record)
    return record


async def run_cert_scan(domains, db) -> list:
    """Checks every domain concurrently (each probe already offloads its
    blocking socket call to a thread) and returns the persisted records."""
    return list(await asyncio.gather(*(check_domain_certificate(d, db) for d in domains)))


async def ssl_cert_monitor_worker():
    """Background loop: mirrors services/dns_verification_worker.py's
    shape -- try/except per tick so one bad scan cannot stop the loop, a
    fixed interval between ticks, and a local (function-scoped) import of
    api.domains to avoid a module-load-time circular import (the same
    pattern services/origin_service.py already uses for `from api.tunnels
    import get_proxy_owner`)."""
    print("=" * 50)
    print("Starting SSL Certificate Monitor Worker...")
    print("=" * 50)

    from services.dynamodb_service import DynamoDBService

    db = DynamoDBService()

    while True:
        try:
            from api.domains import _ssl_allowed_set

            domains = await _ssl_allowed_set()
            if domains:
                print(f"[SSL Cert Monitor] Checking {len(domains)} domain(s)...")
                await run_cert_scan(sorted(domains), db)
        except Exception as e:
            print(f"[SSL Cert Monitor] Error in scan loop: {e}")

        await asyncio.sleep(CERT_CHECK_INTERVAL_SECONDS)
