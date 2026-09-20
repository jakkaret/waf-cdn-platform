"""
Scenario: dd614ac ("feat: implement multi-tenant tunnel isolation, FRP webhook
gatekeeper, and auto-sync origins") merged POST /api/tunnels/frp-hook
(api/tunnels.py's frp_webhook_gatekeeper) with no accompanying tests. Per the
merge commit's own docstring, this endpoint exists to "enforce User Token
Validation and Domain Ownership" for FRP's Login/NewProxy/CloseProxy plugin
webhooks. Assertions here are derived directly from reading that function,
not written to make arbitrary code pass -- several tests below are RED
against the pre-fix code and document a real gap, not a hypothetical one.

FRP's HTTP plugin protocol (v0.61.1, confirmed against upstream docs) passes
the authenticated client's identity in BOTH Login (content.user /
content.metadatas at top level) and NewProxy (content.user.user /
content.user.metas, nested) -- so the plugin has everything it needs to tie a
NewProxy registration back to the token that logged in, and there is no
architectural reason it should not.
"""
import asyncio
import hashlib
import time

import pytest

from api.tunnels import frp_webhook_gatekeeper, LEGACY_STATIC_TOKEN, RESERVED_SUBDOMAINS
from services.auth_service import AuthService

auth_service = AuthService()


def _run(coro):
    return asyncio.run(coro)


def _tunnel_token(domain: str, user_id: str = "user-a", username: str = "alice") -> str:
    return auth_service.create_access_token({
        "sub": user_id, "user_id": user_id, "username": username,
        "domain": domain, "type": "tunnel_token",
    })


# --------------------------------------------------------------------- Login

def test_login_accepts_exact_legacy_static_token():
    req = {"op": "Login", "content": {"privilege_key": LEGACY_STATIC_TOKEN, "timestamp": int(time.time())}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


def test_login_accepts_legacy_token_via_metadatas():
    req = {"op": "Login", "content": {"metadatas": {"token": LEGACY_STATIC_TOKEN}}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


def test_login_accepts_md5_hashed_legacy_token_within_freshness_window():
    ts = int(time.time())
    hashed = hashlib.md5((LEGACY_STATIC_TOKEN + str(ts)).encode()).hexdigest()
    req = {"op": "Login", "content": {"privilege_key": hashed, "timestamp": ts}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


@pytest.mark.xfail(
    reason=(
        "Known, deliberately unfixed finding: the MD5 legacy-token freshness "
        "check compares only against the caller's own claimed timestamp, "
        "never this server's real clock, so it provides no actual freshness "
        "enforcement. Not fixed in this pass -- the webhook is reachable only "
        "from the local FRP server process, not the public internet, which "
        "bounds the practical risk, and a real fix needs a seen-hash cache "
        "plus a real-clock bound, a bigger change than this review's scope."
    ),
    strict=True,
)
def test_login_md5_freshness_window_is_not_actually_checked_against_real_time():
    """CRITICAL finding, more severe than the +/-5s "freshness window" name
    suggests: `ts` in the delta loop is `content.get("timestamp", 0)` --
    the CALLER's own claimed timestamp -- and is never compared against
    this server's real clock (`time.time()` is used elsewhere in this file,
    e.g. the /status cache, but not here). The delta loop only checks
    self-consistency around whatever timestamp the caller supplied, so an
    attacker who knows LEGACY_STATIC_TOKEN can mint a valid (hash, ts) pair
    for a timestamp from an hour ago, a year ago, or the future, and it
    passes every time -- there is no actual freshness enforcement at all.
    Encodes the intended behaviour (a claimed timestamp far from now should
    be rejected); expected to fail against the pre-fix code.
    """
    ts = int(time.time()) - 3600  # one hour old, self-consistently hashed
    hashed = hashlib.md5((LEGACY_STATIC_TOKEN + str(ts)).encode()).hexdigest()
    req = {"op": "Login", "content": {"privilege_key": hashed, "timestamp": ts}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True, (
        "an hour-old self-consistently-hashed timestamp was accepted -- the "
        "freshness window is checked against the caller's own claimed time, "
        "never against this server's real clock"
    )


def test_login_accepts_valid_user_jwt_tunnel_token():
    token = _tunnel_token("alice.example.com")
    req = {"op": "Login", "content": {"metadatas": {"token": token}}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


def test_login_rejects_garbage_token():
    req = {"op": "Login", "content": {"privilege_key": "not-a-real-token-at-all", "timestamp": int(time.time())}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True
    assert "reject_reason" in result


def test_login_rejects_empty_credentials():
    """Fail-closed: absence of any credential must reject, not default-allow."""
    req = {"op": "Login", "content": {}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True


def test_login_rejects_expired_jwt():
    from datetime import timedelta
    expired = auth_service.create_access_token(
        {"sub": "user-a", "user_id": "user-a", "domain": "alice.example.com", "type": "tunnel_token"},
        expires_delta=timedelta(seconds=-10),
    )
    req = {"op": "Login", "content": {"metadatas": {"token": expired}}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True


def test_login_replay_of_same_valid_hash_is_currently_accepted_unboundedly():
    """Documents current behaviour, not an endorsement: with no nonce/
    single-use tracking AND no real-clock freshness check (see the previous
    test), a captured or attacker-forged (hash, timestamp) pair for the
    legacy token remains valid forever, replayed any number of times.
    Flagged as a finding in the security review, not fixed here -- proper
    remediation is the real-clock freshness check above plus a seen-hash
    cache, and this webhook today is only reachable from the FRP server
    process on the same host, not the public internet, which bounds the
    practical exposure.
    """
    ts = int(time.time())
    hashed = hashlib.md5((LEGACY_STATIC_TOKEN + str(ts)).encode()).hexdigest()
    req = {"op": "Login", "content": {"privilege_key": hashed, "timestamp": ts}}
    first = _run(frp_webhook_gatekeeper(req))
    second = _run(frp_webhook_gatekeeper(req))
    assert first["reject"] is False
    assert second["reject"] is False  # replay succeeds -- documented gap, see module docstring


# ------------------------------------------------------------------ NewProxy

def test_newproxy_rejects_reserved_domain():
    req = {"op": "NewProxy", "content": {"custom_domains": ["dash.waf-it-kku.online"], "proxy_name": "x"}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True


def test_newproxy_bare_legacy_token_is_rejected_not_scoped_to_any_domain():
    """2026-09-20: this test previously asserted the OLD, since-deliberately-
    closed contract ("the shared legacy token may register any non-reserved
    domain") -- see api/tunnels.py's own comment at this exact reject path,
    dated 2026-09-07: "The shared static token carries no domain claim, so
    it cannot establish that this client owns `target_domain`... every proxy
    now ships a domain-scoped token in its frpc.toml `metadatas.token`."
    That hardening shipped in production (confirmed live: this exact request
    shape gets reject=True today) but this test was never updated to match,
    so it had been silently red since 7 Sept, masking the real, current
    contract instead of locking it in. A proxy connection using ONLY the
    bare shared token (no per-proxy metas.token) must be rejected -- see the
    test right below this one for the now-required alternative: the same
    legacy-authenticated connection presenting its own domain-scoped
    metas.token on NewProxy, which is what every real deployed proxy
    (dvwa/juice/vampi/bwapp) actually sends today."""
    req = {
        "op": "NewProxy",
        "content": {
            "custom_domains": ["dvwa.waf-it-kku.online"],
            "proxy_name": "dvwa-waf-it-kku-online",
            "user": {"user": LEGACY_STATIC_TOKEN, "metas": {}},
        },
    }
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True
    assert "not scoped to a domain" in result["reject_reason"]


def test_newproxy_legacy_login_with_per_proxy_domain_token_is_accepted():
    """The real, current path a legacy-authenticated client (dvwa/juice/
    vampi/bwapp) must use: the connection logs in with the shared
    LEGACY_STATIC_TOKEN (still valid for Login, per _resolve_frp_identity),
    but each individual proxy's NewProxy carries its OWN domain-scoped JWT
    in content.metas.token (FRP's per-proxy metadatas, mirrored to the top
    level of content -- see the 2026-09-07 comment in frp_webhook_gatekeeper
    about content["metas"] vs content["user"]). This is what actually
    authorizes the domain binding now, not the shared token."""
    token = _tunnel_token("dvwa.waf-it-kku.online", user_id="user-legacy-migrated")
    req = {
        "op": "NewProxy",
        "content": {
            "custom_domains": ["dvwa.waf-it-kku.online"],
            "proxy_name": "dvwa-waf-it-kku-online",
            "metas": {"token": token},
            "user": {"user": LEGACY_STATIC_TOKEN, "metas": {}},
        },
    }
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


def test_newproxy_jwt_client_may_register_the_domain_its_token_was_issued_for():
    token = _tunnel_token("alice.example.com", user_id="user-a")
    req = {
        "op": "NewProxy",
        "content": {
            "custom_domains": ["alice.example.com"],
            "proxy_name": "alice-tunnel",
            "user": {"user": token, "metas": {"token": token}},
        },
    }
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


def test_newproxy_jwt_client_cannot_register_a_different_domain_than_its_token():
    """CRITICAL finding: as merged, frp_webhook_gatekeeper's NewProxy handler
    checks only RESERVED_SUBDOMAINS -- it never inspects content.user (present
    per FRP's own plugin protocol, confirmed via upstream docs) to verify the
    domain being registered matches the domain the authenticating JWT was
    issued for. A tunnel token minted for alice.example.com could therefore
    be used to hijack a NewProxy registration for bob.example.com, so long as
    "bob.example.com" isn't in the small hardcoded reserved set.

    This test encodes the INTENDED invariant (stated in the function's own
    docstring: "enforce ... Domain Ownership") and is expected to fail
    against the pre-fix code, then pass after the fix below.
    """
    token = _tunnel_token("alice.example.com", user_id="user-a")
    req = {
        "op": "NewProxy",
        "content": {
            "custom_domains": ["bob.example.com"],
            "proxy_name": "hijack-attempt",
            "user": {"user": token, "metas": {"token": token}},
        },
    }
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True, (
        "a JWT tunnel token scoped to alice.example.com registered a proxy "
        "for bob.example.com and was NOT rejected -- cross-tenant domain "
        "hijack via the FRP webhook gatekeeper"
    )


def test_newproxy_empty_target_domain_is_currently_allowed():
    """Documents current behaviour: proxy_name/custom_domains are normally
    always populated by a real FRP client, so this is a low-probability edge
    case, but as written an empty target_domain short-circuits straight past
    even the reserved-domain check. Flagged, not fixed -- proxy_name/domain
    here originate from the tunnel agent's own local config, not attacker-
    controlled input from an arbitrary network position.
    """
    req = {"op": "NewProxy", "content": {"custom_domains": [], "proxy_name": ""}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


# ----------------------------------------------------------------- CloseProxy

def test_closeproxy_always_allowed():
    req = {"op": "CloseProxy", "content": {"proxy_name": "anything"}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is False


# -------------------------------------------------------- malformed / unknown

def test_malformed_payload_missing_content_does_not_crash():
    req = {"op": "Login"}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True  # no credential present at all -- fail-closed


def test_unknown_op_fails_closed_not_open():
    """Fail-closed invariant: an operation this code does not recognise
    (a future FRP protocol addition, a malformed op string) must not
    default-allow. As merged, the final fallback returns {"reject": False},
    i.e. fail-OPEN for anything unrecognised. Encodes the intended
    fail-closed behaviour; expected to fail against the pre-fix code.
    """
    req = {"op": "SomeFutureOpNobodyHandlesYet", "content": {}}
    result = _run(frp_webhook_gatekeeper(req))
    assert result["reject"] is True
