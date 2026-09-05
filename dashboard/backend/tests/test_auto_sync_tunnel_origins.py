"""
Scenario: dd614ac merged services/origin_service.py's auto_sync_tunnel_origins()
with no accompanying tests. It is called from GET /api/tunnels/status on every
request (subject to a 3s cache) and is meant to "auto-create Origin + Domain
in DynamoDB for any online tunnel that is not yet registered."

Reading the implementation reveals a CRITICAL tenant-isolation gap: it queries
ALL live FRP proxies (data.get("proxies", []) is every proxy on the shared FRP
server, not scoped to any user) and, for any one not already matched against
the CALLING user's own origins, unconditionally creates a NEW origin owned by
the calling user_id -- with no check for whether some OTHER user has already
claimed that same tunnel as their own origin. Two different users calling
GET /api/tunnels/status for the same online, unclaimed-by-them tunnel will
each get their own origin record for it.

Assertions below are derived from this reading, not written to make the code
pass -- the cross-tenant tests are RED against the pre-fix code and document
the exact hijack path.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

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


def setup_function(_):
    origin_service.db = _FreshFakeDynamoDBService()


# --------------------------------------------------------------- create/basic

def test_create_registers_a_new_origin_for_an_online_unclaimed_tunnel():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert len(created) == 1
    assert created[0]["admin_user_id"] == "user-a"
    assert created[0]["ip"] == "alice.example.com"
    origins = origin_service.get_origins_for_user("user-a")
    assert len(origins) == 1


def test_offline_proxy_is_not_synced():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    proxy["status"] = "offline"
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
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        created = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert created == []  # nothing NEW created
    restored = origin_service.get_origin("existing-1")
    assert restored["status"] == "active"


# --------------------------------------------------------------- duplicate

def test_repeated_sync_calls_do_not_create_duplicate_origins_for_the_same_user():
    proxy = _online_proxy("alice-tunnel", "alice.example.com")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        first = _run(origin_service.auto_sync_tunnel_origins("user-a"))
        second = _run(origin_service.auto_sync_tunnel_origins("user-a"))

    assert len(first) == 1
    assert second == []  # already matched on the second call, nothing new
    assert len(origin_service.get_origins_for_user("user-a")) == 1


# -------------------------------------------------------- tenant isolation

def test_a_tunnel_already_claimed_by_one_user_is_not_reassignable_via_sync():
    """CRITICAL: same online proxy, two different callers. The current
    implementation only checks the CALLING user's own origins for a match
    (`all_user_origins = db.get_origins_by_user(user_id)`), so it has no way
    to see that user-a already claimed this tunnel -- user-b's call creates
    a second, independent origin record for the identical physical tunnel.
    Encodes the intended invariant (a tunnel already owned by someone is not
    auto-claimable by a second account); expected to fail against the
    pre-fix code.
    """
    proxy = _online_proxy("shared-tunnel", "shared.example.com")
    with patch("services.origin_service.httpx.AsyncClient", return_value=_patched_client([proxy])):
        first = _run(origin_service.auto_sync_tunnel_origins("user-a"))
        second = _run(origin_service.auto_sync_tunnel_origins("user-b"))

    assert len(first) == 1
    assert second == [], (
        "user-b's auto-sync call created a second origin for a tunnel "
        "user-a already claimed -- cross-tenant origin hijack via "
        "auto_sync_tunnel_origins"
    )


def test_origin_ownership_is_not_transferable_by_a_different_user_calling_sync():
    """Companion to the above: after user-a legitimately claims a tunnel,
    the DB record's admin_user_id must still say user-a -- not get
    overwritten or duplicated under user-b -- when user-b later syncs.
    """
    proxy = _online_proxy("shared-tunnel", "shared.example.com")
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
