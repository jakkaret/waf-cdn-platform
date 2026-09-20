"""
Scenario: 2026-09-21 -- user asked for a CrowdSec-style cross-tenant threat
signal, opt-in, with an explicit constraint: never share IPs or any
PDPA-sensitive data, only attack *patterns*. Design (reviewed before
writing code):

- The shared unit is (rule_id, attack_type), never an IP, URL, or payload --
  a CRS/custom rule_id is already a generic attack-technique identifier
  (e.g. "942100" = SQLi via libinjection), never victim-specific.
- "Which tenant" is represented only as HMAC(salt, user_id) truncated to 16
  hex chars -- not reversible without the salt (a dedicated env var, never
  JWT_SECRET_KEY, so a JWT leak can't also unmask which tenants share) --
  and even that hash is discarded after PATTERN_RETENTION_HOURS via
  DynamoDB-native TTL (confirmed enabled on waf_threat_patterns 2026-09-21).
- Sharing is opt-in per user (services.auth_service.set_threat_intel_opt_in)
  and checked *fresh* on every write and every read -- no caching of the
  flag itself -- so opting out takes effect on the very next attack, not
  after some TTL. That direction (opt-out must be immediate) is the actual
  privacy failure mode, not opt-in lag.
- A tenant must itself be opted in to see the trending feed at all
  (reciprocity, same spirit as CrowdSec's community wall).

The first test below is deliberately the one that can hurt the most if it
fails: an opted-out tenant's attacks must never reach the shared table at
all -- asserted on the table being empty, not on an API response.
"""
import datetime as dt

import pytest

import services.threat_intel as threat_intel


class _FakeUsers:
    """Minimal stand-in for auth_service.get_user_by_id, keyed by user_id."""

    def __init__(self):
        self.users = {}

    def add(self, user_id: str, share_threat_intel: bool):
        self.users[user_id] = {"user_id": user_id, "share_threat_intel": share_threat_intel}

    def get_user_by_id(self, user_id: str):
        return self.users.get(user_id)

    def set_threat_intel_opt_in(self, user_id: str, enabled: bool):
        self.users.setdefault(user_id, {"user_id": user_id})["share_threat_intel"] = enabled


# ---------------------------------------------------------------------------
# _tenant_hash: deterministic, per-user, not the raw id
# ---------------------------------------------------------------------------

def test_tenant_hash_is_deterministic_for_the_same_user():
    a = threat_intel._tenant_hash("user-123", salt="test-salt")
    b = threat_intel._tenant_hash("user-123", salt="test-salt")
    assert a == b


def test_tenant_hash_differs_for_different_users():
    a = threat_intel._tenant_hash("user-123", salt="test-salt")
    b = threat_intel._tenant_hash("user-456", salt="test-salt")
    assert a != b


def test_tenant_hash_never_contains_the_raw_user_id():
    h = threat_intel._tenant_hash("user-123", salt="test-salt")
    assert "user-123" not in h


def test_tenant_hash_differs_with_a_different_salt():
    # Proves the salt actually participates -- not just decorative.
    a = threat_intel._tenant_hash("user-123", salt="salt-one")
    b = threat_intel._tenant_hash("user-123", salt="salt-two")
    assert a != b


# ---------------------------------------------------------------------------
# record_pattern_hit: the shared counter itself
# ---------------------------------------------------------------------------

def test_record_pattern_hit_never_writes_the_raw_user_id_or_any_ip_or_url(db):
    threat_intel.record_pattern_hit(
        "user-alice", "942100", "SQL Injection", db=db,
        now=dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc),
    )
    rows = db.threat_patterns_table.scan().get("Items", [])
    assert len(rows) == 1
    row = rows[0]
    blob = str(row)
    assert "user-alice" not in blob
    # Field-level check that no ip/url/payload field ever got introduced.
    assert set(row.keys()) <= {
        "pattern_key", "rule_id", "attack_type", "time_bucket",
        "hit_count", "tenant_hashes", "updated_at", "expires_at",
    }


def test_record_pattern_hit_sets_a_ttl_in_the_future(db):
    now = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=now)
    row = db.threat_patterns_table.scan()["Items"][0]
    assert row["expires_at"] > int(now.timestamp())


def test_record_pattern_hit_from_two_different_users_counts_two_distinct_tenants(db):
    now = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=now)
    threat_intel.record_pattern_hit("user-bob", "942100", "SQL Injection", db=db, now=now)

    rows = db.threat_patterns_table.scan()["Items"]
    assert len(rows) == 1  # same rule_id + same hour bucket -> one row
    assert rows[0]["hit_count"] == 2
    assert len(rows[0]["tenant_hashes"]) == 2


def test_record_pattern_hit_from_the_same_user_twice_does_not_inflate_distinct_count(db):
    now = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=now)
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=now)

    row = db.threat_patterns_table.scan()["Items"][0]
    assert row["hit_count"] == 2  # raw hits still counted
    assert len(row["tenant_hashes"]) == 1  # but only one real contributor


# ---------------------------------------------------------------------------
# get_trending_patterns: read side, gated by the requester's own opt-in
# ---------------------------------------------------------------------------

def test_get_trending_patterns_refuses_a_requester_who_has_not_opted_in(db, monkeypatch):
    users = _FakeUsers()
    users.add("user-carol", share_threat_intel=False)
    monkeypatch.setattr(threat_intel, "auth_service", users)

    with pytest.raises(PermissionError):
        threat_intel.get_trending_patterns("user-carol", db=db)


def test_get_trending_patterns_aggregates_across_hour_buckets_in_the_window(db, monkeypatch):
    users = _FakeUsers()
    users.add("user-carol", share_threat_intel=True)
    monkeypatch.setattr(threat_intel, "auth_service", users)

    t0 = dt.datetime(2026, 9, 21, 10, 0, tzinfo=dt.timezone.utc)
    t1 = dt.datetime(2026, 9, 21, 11, 0, tzinfo=dt.timezone.utc)
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=t0)
    threat_intel.record_pattern_hit("user-bob", "942100", "SQL Injection", db=db, now=t1)

    results = threat_intel.get_trending_patterns(
        "user-carol", db=db, now=dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc),
        window_hours=24, min_distinct_tenants=2,
    )

    assert len(results) == 1
    assert results[0]["rule_id"] == "942100"
    assert results[0]["total_hits"] == 2
    assert results[0]["distinct_tenants"] == 2


def test_get_trending_patterns_hides_a_pattern_seen_from_only_one_tenant(db, monkeypatch):
    # A single opted-in tenant's own pattern must not read as "community
    # trending" -- that would deanonymize them as the sole source.
    users = _FakeUsers()
    users.add("user-carol", share_threat_intel=True)
    monkeypatch.setattr(threat_intel, "auth_service", users)

    now = dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc)
    threat_intel.record_pattern_hit("user-alice", "930120", "Path Traversal", db=db, now=now)

    results = threat_intel.get_trending_patterns(
        "user-carol", db=db, now=now, window_hours=24, min_distinct_tenants=2,
    )
    assert results == []


def test_get_trending_patterns_excludes_hits_outside_the_time_window(db, monkeypatch):
    users = _FakeUsers()
    users.add("user-carol", share_threat_intel=True)
    monkeypatch.setattr(threat_intel, "auth_service", users)

    old = dt.datetime(2026, 9, 18, 10, 0, tzinfo=dt.timezone.utc)  # 3 days before "now"
    threat_intel.record_pattern_hit("user-alice", "942100", "SQL Injection", db=db, now=old)
    threat_intel.record_pattern_hit("user-bob", "942100", "SQL Injection", db=db, now=old)

    results = threat_intel.get_trending_patterns(
        "user-carol", db=db, now=dt.datetime(2026, 9, 21, 12, 0, tzinfo=dt.timezone.utc),
        window_hours=24, min_distinct_tenants=2,
    )
    assert results == []


# ---------------------------------------------------------------------------
# record_pattern_hit_for_domain: the real integration seam -- resolves a
# domain to its owning tenant and respects that tenant's *own* live opt-in
# flag, fetched fresh (never cached) so opt-out is immediate.
# ---------------------------------------------------------------------------

def test_an_opted_out_tenants_attack_never_reaches_the_shared_table_at_all(db, monkeypatch):
    """The test that matters most: assert on the table, not on a response."""
    users = _FakeUsers()
    users.add("user-victim", share_threat_intel=False)
    monkeypatch.setattr(threat_intel, "auth_service", users)
    monkeypatch.setattr(
        threat_intel, "_domain_owner_map", lambda now=None: {"quiet-tenant.example.com": "user-victim"}
    )

    threat_intel.record_pattern_hit_for_domain(
        "quiet-tenant.example.com", "942100", "SQL Injection", db=db,
    )

    assert db.threat_patterns_table.scan()["Items"] == []


def test_an_opted_in_tenants_attack_is_recorded_via_domain_resolution(db, monkeypatch):
    users = _FakeUsers()
    users.add("user-sharer", share_threat_intel=True)
    monkeypatch.setattr(threat_intel, "auth_service", users)
    monkeypatch.setattr(
        threat_intel, "_domain_owner_map", lambda now=None: {"sharer-tenant.example.com": "user-sharer"}
    )

    threat_intel.record_pattern_hit_for_domain(
        "sharer-tenant.example.com", "942100", "SQL Injection", db=db,
    )

    rows = db.threat_patterns_table.scan()["Items"]
    assert len(rows) == 1
    assert rows[0]["hit_count"] == 1


def test_a_domain_with_no_resolvable_owner_is_silently_skipped_not_crashed(db, monkeypatch):
    monkeypatch.setattr(threat_intel, "_domain_owner_map", lambda now=None: {})

    threat_intel.record_pattern_hit_for_domain(
        "unknown-domain.example.com", "942100", "SQL Injection", db=db,
    )

    assert db.threat_patterns_table.scan()["Items"] == []


def test_opting_out_takes_effect_on_the_very_next_attack_no_stale_sharing(db, monkeypatch):
    """Simulates: tenant shares once, then opts out, then attacked again --
    the second attack must not appear, proving the flag is read fresh."""
    users = _FakeUsers()
    users.add("user-flippy", share_threat_intel=True)
    monkeypatch.setattr(threat_intel, "auth_service", users)
    monkeypatch.setattr(
        threat_intel, "_domain_owner_map", lambda now=None: {"flippy.example.com": "user-flippy"}
    )

    threat_intel.record_pattern_hit_for_domain("flippy.example.com", "942100", "SQL Injection", db=db)
    assert len(db.threat_patterns_table.scan()["Items"]) == 1

    users.set_threat_intel_opt_in("user-flippy", False)  # opts out

    threat_intel.record_pattern_hit_for_domain("flippy.example.com", "930120", "Path Traversal", db=db)
    rows = db.threat_patterns_table.scan()["Items"]
    # Still only the one row from before the opt-out -- nothing new landed.
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "942100"
