"""
Scenario: 2026-09-21 -- OriginDetail.tsx's "SSL Certificates" tab was fully
fabricated (`domain.ssl_status === 'active' ? success : warning`, defaulting
to the literal string 'ACTIVE' for every domain, plus a hardcoded "TLS 1.3 -
Issuer: Let's Encrypt / ZeroSSL" caption) -- the same bug class already found
and fixed in CDN.tsx earlier in the session. `waf_ssl_certs` existed as a
DynamoDB table reference in DynamoDBService but had zero read/write callers
anywhere in the codebase, confirmed empty.

Investigating what real data source to trust surfaced a second, independent
finding: Main's own Caddy has been failing ACME issuance for
juice/bwapp.waf-it-kku.online for ~2.4 days straight (attempt 19-20/20,
"authorization took too long" / "tls: internal error") because Let's
Encrypt's validation traffic lands on the edge node (45.154.26.91), not on
Main -- confirmed via a real handshake against the public domains: every
domain (juice/dvwa/vampi/bwapp) already has a valid, non-expiring-soon cert
(notAfter 2026-11-22) when probed the way a real client reaches it. Reading
Main's local Caddy certificate store would have reported juice/bwapp as
MISSING while users get a valid cert -- fabricated-but-inverted data. So the
monitor probes the public HTTPS endpoint per domain, the same way a real
client (or curl) does, rather than reading any single node's local cert
store.
"""
import asyncio
import socket
import ssl
import threading
import datetime as dt

import pytest

import services.ssl_cert_monitor as monitor


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Pure functions: parse_not_after / compute_days_remaining / should_alert
# ---------------------------------------------------------------------------

def test_parse_not_after_reads_the_exact_format_ssl_getpeercert_returns():
    # ssl.SSLSocket.getpeercert()['notAfter'] is always this exact strftime
    # shape ("%b %d %H:%M:%S %Y %Z"), e.g. "Nov 22 14:07:01 2026 GMT" --
    # confirmed live against juice.waf-it-kku.online this session.
    parsed = monitor.parse_not_after("Nov 22 14:07:01 2026 GMT")
    assert parsed == dt.datetime(2026, 11, 22, 14, 7, 1, tzinfo=dt.timezone.utc)


def test_compute_days_remaining_rounds_down_to_whole_days():
    not_after = dt.datetime(2026, 10, 15, 12, 0, 0, tzinfo=dt.timezone.utc)
    now = dt.datetime(2026, 10, 10, 0, 0, 0, tzinfo=dt.timezone.utc)
    # 5 days 12 hours left -- must not round up to 6 (a cert with 5 days 1
    # hour left must not read as "6 days remaining, still safe").
    assert monitor.compute_days_remaining(not_after, now) == 5


def test_compute_days_remaining_is_negative_for_an_already_expired_cert():
    not_after = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    now = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc)
    assert monitor.compute_days_remaining(not_after, now) == -4


def test_should_alert_is_false_when_comfortably_within_the_threshold():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert monitor.should_alert(days_remaining=30, last_alerted_at=None, now=now) is False


def test_should_alert_is_true_the_first_time_a_cert_crosses_the_threshold():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert monitor.should_alert(days_remaining=10, last_alerted_at=None, now=now) is True


def test_should_alert_is_false_again_soon_after_already_alerting_once():
    now = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    last_alerted_at = dt.datetime(2026, 1, 1, 6, 0, 0, tzinfo=dt.timezone.utc)  # 6h ago
    # Default cooldown is 24h -- must not re-fire every 6-hour scan tick.
    assert monitor.should_alert(days_remaining=10, last_alerted_at=last_alerted_at, now=now) is False


def test_should_alert_fires_again_once_the_cooldown_has_fully_elapsed():
    now = dt.datetime(2026, 1, 2, 12, 0, 1, tzinfo=dt.timezone.utc)
    last_alerted_at = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)  # >24h ago
    assert monitor.should_alert(days_remaining=10, last_alerted_at=last_alerted_at, now=now) is True


def test_should_alert_is_true_for_an_already_expired_certificate_even_mid_cooldown():
    # A cert going from "expiring soon" to "expired" while still inside the
    # 24h cooldown is a strictly worse state -- must not stay silent.
    now = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    last_alerted_at = dt.datetime(2026, 1, 1, 6, 0, 0, tzinfo=dt.timezone.utc)
    assert monitor.should_alert(days_remaining=-1, last_alerted_at=last_alerted_at, now=now) is True


# ---------------------------------------------------------------------------
# probe_certificate: one real (local, self-signed) TLS handshake -- proves
# the socket/SNI/parsing wiring actually works, not just the pure math.
# ---------------------------------------------------------------------------

def _start_local_tls_server(cert_pem: str, key_pem: str, tmp_path):
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_text(cert_pem)
    key_file.write_text(key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.bind(("127.0.0.1", 0))
    raw_sock.listen(1)
    port = raw_sock.getsockname()[1]

    def _serve_once():
        try:
            conn, _ = raw_sock.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(4096)
        except Exception:
            pass

    thread = threading.Thread(target=_serve_once, daemon=True)
    thread.start()
    return port, thread


@pytest.fixture()
def self_signed_cert(tmp_path):
    """Generate a throwaway self-signed cert/key pair using the `cryptography`
    library already vendored in this project (used by services/dns_service.py
    style modules elsewhere)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    not_valid_before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    not_valid_after = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=9)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, not_valid_after


def test_probe_certificate_reads_a_real_verified_handshakes_not_after_and_issuer(
    tmp_path, self_signed_cert, monkeypatch
):
    """Full path under test, including chain verification -- production
    monitors real public domains (Let's Encrypt/ZeroSSL), where verifying
    against the default trust store is exactly what catches a broken chain
    or expired root, real failure modes a real client would also hit. Here
    the test's own self-signed cert is trusted as its own root CA (via
    cafile=), so the *same* verified code path production uses is what
    gets exercised -- nothing is disabled for the test."""
    cert_pem, key_pem, not_valid_after = self_signed_cert
    port, _thread = _start_local_tls_server(cert_pem, key_pem, tmp_path)

    cert_file = tmp_path / "cert.pem"  # written by _start_local_tls_server above

    real_create_connection = socket.create_connection

    def _redirect(address, *args, **kwargs):
        return real_create_connection(("127.0.0.1", port), *args, **kwargs)

    monkeypatch.setattr(monitor.socket, "create_connection", _redirect)
    # functools.partial binds the *original* ssl.create_default_context
    # function object right now -- a plain closure calling
    # ssl.create_default_context(...) from inside the replacement would look
    # up that name again at call time and find itself (self-recursion:
    # monitor.ssl IS the real ssl module, so this monkeypatch mutates the
    # one shared module attribute).
    import functools
    monkeypatch.setattr(
        monitor.ssl, "create_default_context",
        functools.partial(ssl.create_default_context, cafile=str(cert_file)),
    )

    result = monitor.probe_certificate("test.local")

    assert result["status"] == "ok"
    assert result["issuer"] == "test.local"
    assert result["not_after"] == monitor.parse_not_after(
        not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")
    ).isoformat()


def test_probe_certificate_reports_a_connection_failure_as_an_error_not_a_crash():
    # Nothing listens on this port -- must degrade to a structured error,
    # never raise (one unreachable domain must not kill the whole scan).
    result = monitor.probe_certificate("127.0.0.1", port=1)
    assert result["status"] == "error"
    assert "error" in result


def test_probe_certificate_rejects_a_self_signed_cert_when_not_explicitly_trusted(
    tmp_path, self_signed_cert, monkeypatch
):
    """Regression guard: the production code path must actually verify the
    chain -- without the test's cafile override, a self-signed cert must be
    reported as an error, the same as a real client would refuse it."""
    cert_pem, key_pem, _not_valid_after = self_signed_cert
    port, _thread = _start_local_tls_server(cert_pem, key_pem, tmp_path)

    real_create_connection = socket.create_connection

    def _redirect(address, *args, **kwargs):
        return real_create_connection(("127.0.0.1", port), *args, **kwargs)

    monkeypatch.setattr(monitor.socket, "create_connection", _redirect)

    result = monitor.probe_certificate("test.local")

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# check_domain_certificate: orchestration with injected probe/db/alert
# ---------------------------------------------------------------------------

class _FakeTable:
    """waf_ssl_certs' real key schema is HASH="id" (confirmed via
    describe_table 2026-09-21) -- see services/ssl_cert_monitor.py's
    _persist_cert_record for why it's keyed by the domain string itself."""

    def __init__(self):
        self.rows = {}

    def get_item(self, Key):
        row = self.rows.get(Key["id"])
        return {"Item": row} if row else {}

    def put_item(self, Item):
        self.rows[Item["id"]] = dict(Item)
        return {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues=None,
                     ExpressionAttributeNames=None, **_kw):
        row = self.rows.setdefault(Key["id"], {"id": Key["id"]})
        # Minimal SET-only support -- the only shape check_domain_certificate
        # uses. Resolves #fN placeholders via ExpressionAttributeNames, since
        # production code now always aliases field names (caught live:
        # "status" is a DynamoDB reserved word and a bare `status = :v`
        # expression is rejected by real AWS).
        names = ExpressionAttributeNames or {}
        assert UpdateExpression.startswith("SET ")
        assignments = UpdateExpression[4:].split(",")
        for a in assignments:
            name_tok, val_token = (p.strip() for p in a.split("="))
            name = names.get(name_tok, name_tok)
            row[name] = ExpressionAttributeValues[val_token]
        return {}


class _FakeDB:
    def __init__(self):
        self.ssl_certs_table = _FakeTable()


def test_check_domain_certificate_persists_a_healthy_result_without_alerting():
    db = _FakeDB()
    alerts_sent = []

    async def fake_probe(domain):
        return {
            "status": "ok",
            "not_after": "2026-12-25T00:00:00+00:00",
            "issuer": "Let's Encrypt",
        }

    async def fake_alert(*args, **kwargs):
        alerts_sent.append((args, kwargs))

    now = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    record = _run(monitor.check_domain_certificate(
        "safe.example.com", db, now=now, probe=fake_probe, send_alert=fake_alert
    ))

    assert record["status"] == "ok"
    assert record["days_remaining"] == 54
    assert alerts_sent == []
    assert db.ssl_certs_table.rows["safe.example.com"]["days_remaining"] == 54


def test_check_domain_certificate_alerts_once_when_crossing_the_threshold():
    db = _FakeDB()
    alerts_sent = []

    async def fake_probe(domain):
        return {"status": "ok", "not_after": "2026-11-05T00:00:00+00:00", "issuer": "Let's Encrypt"}

    async def fake_alert(domain, days_remaining, not_after):
        alerts_sent.append((domain, days_remaining, not_after))

    now = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    record = _run(monitor.check_domain_certificate(
        "expiring.example.com", db, now=now, probe=fake_probe, send_alert=fake_alert
    ))

    assert record["days_remaining"] == 4
    assert len(alerts_sent) == 1
    assert alerts_sent[0][0] == "expiring.example.com"
    assert "last_alerted_at" in db.ssl_certs_table.rows["expiring.example.com"]


def test_check_domain_certificate_does_not_alert_twice_inside_the_cooldown():
    db = _FakeDB()
    db.ssl_certs_table.rows["expiring.example.com"] = {
        "domain": "expiring.example.com",
        "last_alerted_at": "2026-11-01T06:00:00+00:00",
    }
    alerts_sent = []

    async def fake_probe(domain):
        return {"status": "ok", "not_after": "2026-11-05T00:00:00+00:00", "issuer": "Let's Encrypt"}

    async def fake_alert(*a, **kw):
        alerts_sent.append((a, kw))

    now = dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=dt.timezone.utc)  # 6h after last alert
    _run(monitor.check_domain_certificate(
        "expiring.example.com", db, now=now, probe=fake_probe, send_alert=fake_alert
    ))

    assert alerts_sent == []


def test_check_domain_certificate_persists_a_probe_error_without_crashing():
    db = _FakeDB()

    async def fake_probe(domain):
        return {"status": "error", "error": "connection refused"}

    async def fake_alert(*a, **kw):
        pass

    now = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    record = _run(monitor.check_domain_certificate(
        "unreachable.example.com", db, now=now, probe=fake_probe, send_alert=fake_alert
    ))

    assert record["status"] == "error"
    assert record["days_remaining"] is None
    assert db.ssl_certs_table.rows["unreachable.example.com"]["status"] == "error"
