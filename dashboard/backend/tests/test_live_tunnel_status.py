"""
Scenario: 2026-09-19 added a "is this tunnel actually connected right now"
indicator, separate from an origin's CRUD lifecycle `status`
(active/archived/pending), which never reflected live connectivity at all --
an origin stayed "ACTIVE" forever even after its tunnel process died.

Covers the two pieces with no prior coverage:
  - api/origins.py's _tunnel_is_online(): a real bug caught during manual
    verification of this exact feature. FRP namespaces a proxy's live name
    with the connection identity for shared/legacy-token clients (e.g.
    "<legacy-token>.dvwa-waf-it-kku-online"), but origin records created at
    different points in this system's history stored `tunnel_name` both with
    and without that prefix -- exact equality silently reported real, online
    tunnels as disconnected.
  - services/origin_service.py's get_live_online_proxy_names(): a 60s
    process-wide cache in front of the FRP dashboard poll, with a force=True
    escape hatch for the Origins page's manual refresh button, added on
    explicit request to avoid hammering FRP on every page load.

Also covers metadatas.port -- the local port a tunnel's origin/status
response now shows is read from conf.metadatas.port. frps' dashboard API
genuinely never returns conf.localPort at all (confirmed against a live
proxy), so the tunnel config generator embeds the port in metadatas instead;
these tests document why the localPort/local_port keys in conf must still be
checked too (pre-fix tunnel configs).
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import api.origins as origins_module
import services.origin_service as origin_service


def _run(coro):
    return asyncio.run(coro)


def setup_function(_):
    origin_service._LIVE_PROXIES_CACHE = None
    import api.tunnels as tunnels_module
    tunnels_module._PROXY_OWNERS.clear()


# --------------------------------------------------- _tunnel_is_online match

@pytest.mark.parametrize(
    "tunnel_name, online_names, expected",
    [
        ("dvwa-waf-it-kku-online", {"dvwa-waf-it-kku-online"}, True),
        # Stored bare, live name carries the legacy-token prefix FRP adds.
        ("dvwa-waf-it-kku-online", {"28cda1cc...token.dvwa-waf-it-kku-online"}, True),
        # Stored with the prefix already (newer records), live name matches exactly.
        ("28cda1cc...token.dvwa-waf-it-kku-online", {"28cda1cc...token.dvwa-waf-it-kku-online"}, True),
        ("dvwa-waf-it-kku-online", {"juice-waf-it-kku-online"}, False),
        ("dvwa-waf-it-kku-online", set(), False),
        ("", {"dvwa-waf-it-kku-online"}, False),
    ],
)
def test_tunnel_is_online_tolerant_match(tunnel_name, online_names, expected):
    assert origins_module._tunnel_is_online(tunnel_name, online_names) is expected


def test_attach_live_status_leaves_non_tunnel_origins_as_none():
    out = origins_module._attach_live_status(
        [{"id": "o1", "is_tunnel": False, "status": "active"}], online_names=set()
    )
    assert out[0]["live_connected"] is None


def test_attach_live_status_does_not_touch_crud_status_field():
    """`status` is a separate concept (CRUD lifecycle) from `live_connected`
    (read-time computed) -- attaching live status must never overwrite it."""
    out = origins_module._attach_live_status(
        [{"id": "o1", "is_tunnel": True, "tunnel_name": "x", "status": "active"}],
        online_names=set(),
    )
    assert out[0]["status"] == "active"
    assert out[0]["live_connected"] is False


# ------------------------------------------------- get_live_online_proxy_names

def _fake_frp_response(proxies):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"proxies": proxies}
    return resp


def _patched_client(proxies=None, exc=None):
    client_cm = MagicMock()
    client_instance = MagicMock()
    if exc:
        client_instance.get = AsyncMock(side_effect=exc)
    else:
        client_instance.get = AsyncMock(return_value=_fake_frp_response(proxies or []))
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=False)
    return client_cm


def test_returns_only_proxies_with_status_online():
    proxies = [
        {"name": "a", "status": "online"},
        {"name": "b", "status": "offline"},
        {"name": "c", "status": "online"},
    ]
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client(proxies)):
        names = _run(origin_service.get_live_online_proxy_names(force=True))
    assert names == {"a", "c"}


def test_result_is_cached_so_a_second_call_does_not_poll_again():
    call_count = {"n": 0}

    def _client_factory(*a, **kw):
        call_count["n"] += 1
        return _patched_client([{"name": "a", "status": "online"}])

    with patch("services.origin_service.httpx.AsyncClient", side_effect=_client_factory):
        first = _run(origin_service.get_live_online_proxy_names())
        second = _run(origin_service.get_live_online_proxy_names())

    assert first == second == {"a"}
    assert call_count["n"] == 1, "second call should have used the 60s cache, not polled FRP again"


def test_force_true_bypasses_the_cache():
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([{"name": "a", "status": "online"}])):
        _run(origin_service.get_live_online_proxy_names())

    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([{"name": "b", "status": "online"}])):
        forced = _run(origin_service.get_live_online_proxy_names(force=True))

    assert forced == {"b"}, "force=True must re-poll instead of returning the stale cached {'a'}"


def test_frp_unreachable_returns_stale_cache_instead_of_a_false_all_offline():
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([{"name": "a", "status": "online"}])):
        _run(origin_service.get_live_online_proxy_names())

    with patch("services.origin_service.httpx.AsyncClient", side_effect=Exception("connection refused")):
        result = _run(origin_service.get_live_online_proxy_names(force=True))

    assert result == {"a"}, "a transient FRP outage should not make every real tunnel look disconnected"


def test_frp_unreachable_with_no_prior_cache_returns_empty_not_a_crash():
    with patch("services.origin_service.httpx.AsyncClient", side_effect=Exception("connection refused")):
        result = _run(origin_service.get_live_online_proxy_names(force=True))
    assert result == set()


# --------------------------------------------------------------- metadatas.port

def test_auto_create_reads_port_from_metadatas_when_localport_is_absent():
    """frps' dashboard API never returns conf.localPort (confirmed live) --
    the tunnel config generator embeds the port in metadatas instead, and
    this is the only reliable source auto-create has. Uses the conftest
    autouse fixture's already-patched origin_service.db (a fresh
    FakeDynamoDBService per test), same as every other test in this file."""
    import api.tunnels as tunnels_module
    tunnels_module._PROXY_OWNERS["alice-tunnel"] = "user-a"

    proxy = {
        "name": "alice-tunnel",
        "status": "online",
        "conf": {
            "customDomains": ["alice.example.com"],
            "localIP": "127.0.0.1",
            # localPort deliberately absent, as frps genuinely never sends it.
            "metadatas": {"token": "irrelevant-here", "port": "9090"},
        },
    }
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert created[0]["port"] == 9090
