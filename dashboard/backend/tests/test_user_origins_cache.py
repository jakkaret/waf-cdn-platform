"""
Scenario: 2026-09-20 perf fix -- get_origins_for_user() (db.get_origins_by_user,
a Query against the admin_user_id-index GSI) had no caching at all, unlike
origins_table.scan() (see the 2026-09-20 dedup fix in origin_service.py) --
measured at the same ~240-255ms cross-region DynamoDB cost per call. Real
traffic to GET /api/origins is dominated by repeated polls (the frontend
refetches this endpoint periodically), so this cost was paid fresh on every
single poll even though the answer rarely changes within a few seconds.
This locks in: a short-TTL, per-user cache that (a) actually avoids the
repeat DB call within its window, (b) never leaks one user's origins into
another user's cache entry, (c) expires on its own after the TTL, and (d)
is invalidated immediately by every write path rather than waiting out the
TTL, so a just-created/updated/deleted/restored origin is visible right away.
"""
import time
from unittest.mock import MagicMock

import pytest

import services.origin_service as origin_service


def test_repeated_calls_within_ttl_hit_the_cache_not_the_db(monkeypatch):
    spy = MagicMock(wraps=origin_service.db.get_origins_by_user)
    monkeypatch.setattr(origin_service.db, "get_origins_by_user", spy)

    origin_service.get_origins_for_user("user-a")
    origin_service.get_origins_for_user("user-a")
    origin_service.get_origins_for_user("user-a")

    assert spy.call_count == 1, "a repeated call within the TTL window must not re-query DynamoDB"


def test_cache_does_not_leak_between_different_users(monkeypatch):
    calls = []
    real = origin_service.db.get_origins_by_user

    def _spy(admin_user_id):
        calls.append(admin_user_id)
        return real(admin_user_id)

    monkeypatch.setattr(origin_service.db, "get_origins_by_user", _spy)

    origin_service.get_origins_for_user("user-a")
    origin_service.get_origins_for_user("user-b")
    origin_service.get_origins_for_user("user-a")  # should hit user-a's own cache entry
    origin_service.get_origins_for_user("user-b")  # should hit user-b's own cache entry

    assert calls == ["user-a", "user-b"], (
        f"expected exactly one real DB call per distinct user, got {calls!r} -- "
        f"a shared (not per-user) cache key would either serve user-a's data to "
        f"user-b or force an unnecessary re-query"
    )


def test_cache_expires_after_ttl(monkeypatch):
    spy = MagicMock(wraps=origin_service.db.get_origins_by_user)
    monkeypatch.setattr(origin_service.db, "get_origins_by_user", spy)

    origin_service.get_origins_for_user("user-a")
    assert spy.call_count == 1

    # Simulate the TTL window having elapsed without a real sleep.
    cached_time, cached_items = origin_service._USER_ORIGINS_CACHE["user-a"]
    origin_service._USER_ORIGINS_CACHE["user-a"] = (
        cached_time - origin_service.USER_ORIGINS_CACHE_TTL - 0.1,
        cached_items,
    )

    origin_service.get_origins_for_user("user-a")
    assert spy.call_count == 2, "a call after the TTL window must re-query DynamoDB, not serve stale data forever"


def test_create_origin_invalidates_the_cache_immediately(monkeypatch):
    origin_service.get_origins_for_user("user-a")
    assert "user-a" in origin_service._USER_ORIGINS_CACHE

    origin_service.create_origin("user-a", "New Origin", "203.0.113.10", 8080)

    assert "user-a" not in origin_service._USER_ORIGINS_CACHE, (
        "creating an origin must invalidate the cache immediately -- otherwise "
        "the user could poll /api/origins right after creating one and not see "
        "it for up to USER_ORIGINS_CACHE_TTL seconds"
    )

    # Clean up so this test doesn't leave data for others in the same run.
    created = [o for o in origin_service.get_origins_for_user("user-a") if o.get("label") == "New Origin"]
    for o in created:
        origin_service.delete_origin(o["id"])


def test_update_delete_restore_all_invalidate_the_cache(monkeypatch):
    origin = origin_service.create_origin("user-b", "Cache Invalidation Target", "203.0.113.11", 8081)
    origin_id = origin["id"]

    def _populate_and_check_invalidated(action):
        origin_service.get_origins_for_user("user-b")  # (re)populate
        assert "user-b" in origin_service._USER_ORIGINS_CACHE
        action()
        assert "user-b" not in origin_service._USER_ORIGINS_CACHE

    _populate_and_check_invalidated(lambda: origin_service.update_origin(origin_id, label="Renamed"))
    _populate_and_check_invalidated(lambda: origin_service.delete_origin(origin_id))
    _populate_and_check_invalidated(lambda: origin_service.restore_origin(origin_id))

    # Clean up.
    origin_service.delete_origin(origin_id)
