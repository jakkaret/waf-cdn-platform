"""
Scenario: 2026-09-22 (Team Workspace + AI Incident Postmortem, overnight
session) -- both features need "what changed and when": Team Workspace so
a team can see who did what, and the postmortem generator so it can read a
real timeline instead of only aggregate request counts (its own concept
card's own example is a paranoia_level change causing a false-positive
spike -- exactly the kind of event this log exists to capture).

Write points are chosen by what a postmortem would actually need to
explain an incident (settings changes, rule approve/reject, origin
updates, viewer/editor grants) -- not by what's easiest to instrument.
Read endpoints are never logged here.
"""
import datetime as dt

import services.audit_log as audit_log


def test_write_audit_event_persists_the_real_fields(db):
    now = dt.datetime(2026, 9, 22, 3, 10, tzinfo=dt.timezone.utc)
    audit_log.write_audit_event(
        scope_id="origin-123",
        actor_user_id="user-alice",
        actor_username="alice",
        action="settings.update",
        summary="เปลี่ยน paranoia_level จาก 1 เป็น 3",
        details={"field": "paranoia_level", "old": 1, "new": 3},
        db=db,
        now=now,
    )
    rows = db.audit_log_table.query(
        KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("scope_id").eq("origin-123")
    )["Items"]
    assert len(rows) == 1
    row = rows[0]
    assert row["actor_user_id"] == "user-alice"
    assert row["action"] == "settings.update"
    assert row["details"]["old"] == 1
    assert row["details"]["new"] == 3
    assert row["timestamp"] == now.isoformat()


def test_write_audit_event_sets_a_future_ttl(db):
    now = dt.datetime(2026, 9, 22, 3, 10, tzinfo=dt.timezone.utc)
    audit_log.write_audit_event(
        scope_id="origin-123", actor_user_id="u", actor_username="u",
        action="origin.update", summary="test", db=db, now=now,
    )
    row = db.audit_log_table.query(
        KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("scope_id").eq("origin-123")
    )["Items"][0]
    assert row["expires_at"] > int(now.timestamp())


def test_two_events_for_the_same_scope_never_collide(db):
    now = dt.datetime(2026, 9, 22, 3, 10, tzinfo=dt.timezone.utc)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="1", db=db, now=now)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="2", db=db, now=now)
    rows = db.audit_log_table.query(
        KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("scope_id").eq("o1")
    )["Items"]
    assert len(rows) == 2


def test_write_audit_event_never_raises_on_a_db_failure(db, monkeypatch):
    def _broken_put_item(**kw):
        raise RuntimeError("dynamodb unreachable")
    monkeypatch.setattr(db.audit_log_table, "put_item", _broken_put_item)
    # Must not raise -- an audit log outage must never break the mutation
    # it's trying to record (e.g. a real settings update should still
    # succeed even if the audit write fails).
    audit_log.write_audit_event(
        scope_id="o1", actor_user_id="u", actor_username="u",
        action="a", summary="s", db=db,
    )


def test_get_audit_log_returns_events_newest_first(db):
    t0 = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    t1 = dt.datetime(2026, 9, 22, 3, 5, tzinfo=dt.timezone.utc)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="first", db=db, now=t0)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="second", db=db, now=t1)

    events = audit_log.get_audit_log("o1", db=db)
    assert [e["summary"] for e in events] == ["second", "first"]


def test_get_audit_log_can_filter_to_a_time_window(db):
    old = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)
    recent = dt.datetime(2026, 9, 22, 3, 0, tzinfo=dt.timezone.utc)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="old", db=db, now=old)
    audit_log.write_audit_event(scope_id="o1", actor_user_id="u", actor_username="u", action="a", summary="recent", db=db, now=recent)

    events = audit_log.get_audit_log(
        "o1", db=db,
        start=dt.datetime(2026, 9, 21, tzinfo=dt.timezone.utc),
        end=dt.datetime(2026, 9, 23, tzinfo=dt.timezone.utc),
    )
    assert [e["summary"] for e in events] == ["recent"]
