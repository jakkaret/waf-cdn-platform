"""
Scenario: dd614ac merged services/origin_service.py's auto_sync_tunnel_origins()
with no accompanying tests. It is called from GET /api/tunnels/status on every
request (subject to a 3s cache) and is meant to "auto-create Origin + Domain
in DynamoDB for any online tunnel that is not yet registered."

Reading the implementation revealed a CRITICAL tenant-isolation gap: it queried
ALL live FRP proxies (data.get("proxies", []) is every proxy on the shared FRP
server, not scoped to any user) and, for any one not already matched against
the CALLING user's own origins, unconditionally created a NEW origin owned by
the calling user_id -- with no check for whether some OTHER user had already
claimed that same tunnel as their own origin, and no check that the caller was
even the one who connected it. Two different users calling GET
/api/tunnels/status for the same online, unclaimed-by-them tunnel would each
get their own origin record for it -- or worse, a second user simply viewing
the page first would silently become the tunnel's owner.

2026-09-19 fix: ownership is no longer inferred from who is calling this
function at all. The FRP webhook gatekeeper (api/tunnels.py,
frp_webhook_gatekeeper's NewProxy handler) already verifies each proxy's
domain-scoped JWT and is the only place that authoritatively knows who minted
it; it records that into module-level api.tunnels._PROXY_OWNERS. This function
now looks the true owner up via api.tunnels.get_proxy_owner(raw_name) and:
  - creates nothing for a proxy NewProxy hasn't authorized yet this process
    (no silent caller-id fallback -- that was the bug),
  - otherwise creates/restores under the true owner, regardless of who is
    calling.
These tests simulate that NewProxy step via _claim(proxy_name, user_id), which
pokes _PROXY_OWNERS the same way the real webhook handler does, then exercise
auto_sync_tunnel_origins the same way GET /api/tunnels/status does.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import api.tunnels as tunnels_module
import services.origin_service as origin_service
from services.dynamodb_service import DynamoDBService
from tests.conftest import InMemoryTable


def _run(coro):
    return asyncio.run(coro)


class _FreshFakeDynamoDBService(DynamoDBService):
    """Same reuse-the-real-business-logic approach as conftest.py's
    FakeDynamoDBService, but with per-instance (not module-shared) backing
    lists -- avoids any dependency on conftest's autouse _STORE-clearing
    fixture's timing relative to this file's setup_function calls.
    """

    def __init__(self):  # noqa: super() intentionally not called - no boto3 here
        self.origins_table = InMemoryTable([])
        self.domains_table = InMemoryTable([])


def _fake_frp_response(proxies):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"proxies": proxies}
    return resp


def _patched_client(proxies):
    """Builds an async-context-manager mock standing in for
    `httpx.AsyncClient(timeout=...)`, whose `.get()` returns `proxies`."""
    client_cm = MagicMock()
    client_instance = MagicMock()
    client_instance.get = AsyncMock(return_value=_fake_frp_response(proxies))
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=False)
    return client_cm


def _online_proxy(name: str, domain: str, local_port: int = 3000) -> dict:
    return {
        "name": name,
        "status": "online",
        "conf": {"customDomains": [domain], "localIP": "127.0.0.1", "localPort": local_port},
    }


def _claim(proxy_name: str, user_id: str) -> None:
    """Simulates the FRP webhook gatekeeper's NewProxy handler recording true
    ownership for `proxy_name` -- the real trigger that makes
    get_proxy_owner(proxy_name) return `user_id`."""
    tunnels_module._PROXY_OWNERS[proxy_name] = user_id


def setup_function(_):
    origin_service.db = _FreshFakeDynamoDBService()
    tunnels_module._PROXY_OWNERS.clear()
    # auto_sync_tunnel_origins now shares origin_service's 60s live-proxy
    # cache (2026-09-20 perf fix, collapsing what used to be two separate
    # FRP polls into one) -- without resetting it here, one test's mocked
    # proxies would leak into the next via that cache instead of each test's
    # own httpx.AsyncClient patch being consulted.
    origin_service._LIVE_PROXIES_CACHE = None


# --------------------------------------------------------------- create/basic

def test_create_registers_a_new_origin_for_an_online_tunnel_whose_owner_newproxy_recorded():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert len(created) == 1
    assert created[0]["admin_user_id"] == "user-a"
    assert created[0]["ip"] == "alice.example.com"
    origins = origin_service.get_origins_for_user("user-a")
    assert len(origins) == 1


def test_online_tunnel_with_no_recorded_owner_is_not_auto_created():
    """The core of the 2026-09-19 fix: NewProxy hasn't fired for this proxy
    in this process (e.g. it was already connected before a backend restart,
    or -- the original bug -- nobody's JWT has ever been verified for it), so
    there is no true owner to assign. The old behaviour of falling back to
    whichever user happens to be viewing the page is exactly the bug being
    prevented; the correct behaviour is to create nothing and wait for the
    tunnel's next reconnect (which re-fires NewProxy)."""
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert created == []
    assert origin_service.get_origins_for_user("user-a") == []


def test_offline_proxy_is_not_synced():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    proxy["status"] = "offline"
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))
    assert created == []


def test_frp_daemon_unreachable_fails_closed_to_no_sync_not_a_crash():
    with patch("services.origin_service.httpx.AsyncClient", side_effect=Exception("connection refused")):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))
    assert created == []


# ------------------------------------------------------------------- update

def test_update_restores_a_matching_archived_origin_instead_of_duplicating():
    origin_service.db.create_origin({
        "id": "existing-1", "admin_user_id": "user-a", "label": "Tunnel (alice.example.com)",
        "ip": "alice.example.com", "port": 3000, "status": "archived",
    })
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert created == []  # nothing NEW created
    restored = origin_service.get_origin("existing-1")
    assert restored["status"] == "active"


def test_archived_origin_restores_even_when_the_viewer_is_not_its_owner():
    """Restoring is a status flip on an existing record, not a new claim --
    it must happen regardless of who is viewing (their own auto-sync call
    still triggers it, since FRP's proxy list isn't scoped to a tenant)."""
    origin_service.db.create_origin({
        "id": "existing-1", "admin_user_id": "user-a", "label": "Tunnel (alice.example.com)",
        "ip": "alice.example.com", "port": 3000, "status": "archived",
    })
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        _run(origin_service.auto_sync_tunnel_origins("user-b"))

    assert origin_service.get_origin("existing-1")["status"] == "active"


# --------------------------------------------------------------- duplicate

def test_repeated_sync_calls_do_not_create_duplicate_origins():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        first = _run(origin_service.auto_sync_tunnel_origins("user-a"))
        second = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert len(first) == 1
    assert second == []  # already matched on the second call, nothing new
    assert len(origin_service.get_origins_for_user("user-a")) == 1


def test_repeated_sync_calls_from_a_different_viewer_do_not_create_duplicates_either():
    """Regression test for a real bug caught during manual verification of
    this exact fix: the original dedup check scanned the CALLING user's own
    origins for a match, so a non-owner viewer's call never found the
    already-created origin and created a second one under the true owner
    every time they loaded the page. The check must be global, not scoped to
    the caller."""
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        _run(origin_service.auto_sync_tunnel_origins("user-a"))
        _run(origin_service.auto_sync_tunnel_origins("user-b"))
        _run(origin_service.auto_sync_tunnel_origins("user-b"))
        _run(origin_service.auto_sync_tunnel_origins("user-a"))

    all_origins = origin_service.db.origins_table.scan()["Items"]
    matching = [o for o in all_origins if o.get("ip") == "alice.example.com"]
    assert len(matching) == 1
    assert matching[0]["admin_user_id"] == "user-a"


# -------------------------------------------------------- tenant isolation

def test_a_tunnel_claimed_by_one_user_is_not_reassignable_via_a_different_viewers_sync():
    """CRITICAL: same online proxy, NewProxy recorded user-a as true owner.
    user-b merely viewing the page (and thus calling auto_sync themselves)
    must never create a second, independent origin record for the identical
    physical tunnel, and must never end up owning it."""
    proxy = _online_proxy("shared-tunnel", "shared.example.com")
    _claim("shared-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        first = _run(origin_service.auto_sync_tunnel_origins("user-a"))
        second = _run(origin_service.auto_sync_tunnel_origins("user-b"))

    assert len(first) == 1
    assert first[0]["admin_user_id"] == "user-a"
    assert second == [], (
        "user-b's auto-sync call created a second origin for a tunnel "
        "user-a already claimed -- cross-tenant origin hijack via "
        "auto_sync_tunnel_origins"
    )


def test_origin_ownership_is_not_transferable_by_a_different_user_calling_sync():
    """Companion to the above: after user-a legitimately claims a tunnel,
    the DB record's admin_user_id must still say user-a -- not get
    overwritten or duplicated under user-b -- when user-b later syncs."""
    proxy = _online_proxy("shared-tunnel", "shared.example.com")
    _claim("shared-tunnel", "user-a")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        _run(origin_service.auto_sync_tunnel_origins("user-a"))
        _run(origin_service.auto_sync_tunnel_origins("user-b"))

    all_origins_for_domain = [
        o for o in origin_service.db.origins_table.scan()["Items"]
        if o.get("ip") == "shared.example.com"
    ]
    owners = {o["admin_user_id"] for o in all_origins_for_domain}
    assert owners == {"user-a"}, (
        f"expected the shared tunnel to remain owned by user-a only, found "
        f"owners={owners} -- a second origin record was created under a "
        f"different account for the same physical tunnel"
    )


def test_proxy_owner_claimed_by_someone_else_than_the_existing_origin_record_is_left_unchanged():
    """Edge case the fix explicitly declined to auto-resolve: an existing
    origin record owned by user-a, but NewProxy's JWT for this proxy now says
    user-b (e.g. the domain changed hands after the original token was
    minted). auto_sync must not silently reassign it -- that decision needs a
    human -- so the record stays owned by user-a and nothing new is created."""
    origin_service.db.create_origin({
        "id": "existing-1", "admin_user_id": "user-a", "label": "Tunnel (alice.example.com)",
        "ip": "alice.example.com", "port": 3000, "status": "active",
    })
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    _claim("alice-tunnel", "user-b")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-b"))

    assert created == []
    assert origin_service.get_origin("existing-1")["admin_user_id"] == "user-a"
