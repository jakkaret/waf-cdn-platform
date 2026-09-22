"""
Scenario: alerts are read and written against a key that identifies an
owner, and /api/alerts/recent stops returning nothing.

waf_alerts was keyed (user_id, alert_id) with user_id hardcoded to
"default-user" by the only writer, so the partition key identified
nothing. Two consequences these tests pin, after the migration to
waf_alerts_v2 (origin_id, alert_id):

1. api/alerts.py filtered /recent on a.get("user_id") == user_id. That
   comparison was false for every real account, so the endpoint returned
   an empty list to every non-admin -- the Alerts page showed no
   incidents while the dashboard's notification feed, which used the
   real scoping, showed unread ones. It now shares that scoping.

2. Mark-as-read built its DynamoDB Key from user_id. Against the new
   schema that raises ValidationException, which the blanket except in
   that handler turns into a 500 -- the same failure mode the previous
   key bug had, so it is asserted here rather than left to be
   rediscovered.
"""
from unittest.mock import MagicMock

import pytest

import api.ai_summary as ai_summary_module


@pytest.fixture()
def db(monkeypatch):
    fake = MagicMock()
    fake.ALERTS_UNATTRIBUTED = "unattributed"
    fake.get_all_alerts.return_value = []
    fake.get_alerts_for_origins.return_value = []
    monkeypatch.setattr(ai_summary_module, "db", fake)
    return fake


def _scope(monkeypatch, origin_ids, domains=()):
    monkeypatch.setattr(
        ai_summary_module,
        "get_user_origins_and_domains",
        lambda _uid: (list(origin_ids), [], list(domains)),
    )


def test_non_admin_reads_alerts_by_partition_key_not_by_scanning(db, monkeypatch):
    _scope(monkeypatch, ["o-mine"], ["mine.example.com"])
    db.get_alerts_for_origins.return_value = [
        {"alert_id": "a-1", "origin_id": "o-mine"}
    ]

    got = ai_summary_module._visible_alerts_for_user({"user_id": "u-1", "role": "viewer"})

    assert [a["alert_id"] for a in got] == ["a-1"]
    # The whole point of the new key: ask for this tenant's partitions
    # instead of reading every tenant's rows and filtering afterwards.
    db.get_alerts_for_origins.assert_called_once()
    assert db.get_alerts_for_origins.call_args[0][0] == ["o-mine"]


def test_unattributed_partition_is_not_handed_to_a_non_admin(db, monkeypatch):
    # get_alerts_for_origins is only ever asked for the user's own
    # origins, so "unattributed" must not appear in the request.
    _scope(monkeypatch, ["o-mine"], ["mine.example.com"])
    ai_summary_module._visible_alerts_for_user({"user_id": "u-1", "role": "viewer"})
    assert "unattributed" not in db.get_alerts_for_origins.call_args[0][0]


def test_admin_still_gets_every_partition(db, monkeypatch):
    db.get_all_alerts.return_value = [
        {"alert_id": "a-1", "origin_id": "o-a"},
        {"alert_id": "a-2", "origin_id": "unattributed"},
    ]
    got = ai_summary_module._visible_alerts_for_user({"user_id": "admin", "role": "admin"})
    assert len(got) == 2
    db.get_alerts_for_origins.assert_not_called()


def test_pre_migration_rows_without_origin_id_still_resolve_by_domain(db, monkeypatch):
    _scope(monkeypatch, ["o-mine"], ["mine.example.com"])
    db.get_all_alerts.return_value = [
        {"alert_id": "a-legacy", "domain": "mine.example.com"},
        {"alert_id": "a-other-legacy", "domain": "someone-else.example.com"},
    ]

    got = ai_summary_module._visible_alerts_for_user({"user_id": "u-1", "role": "viewer"})

    assert [a["alert_id"] for a in got] == ["a-legacy"]


def test_mark_read_uses_the_new_composite_key(db, monkeypatch):
    _scope(monkeypatch, ["o-mine"], ["mine.example.com"])
    db.get_alerts_for_origins.return_value = [
        {"alert_id": "a-1", "origin_id": "o-mine", "read": False}
    ]

    import asyncio

    asyncio.run(
        ai_summary_module.mark_notifications_read(
            alert_id="a-1",
            current_user={"user_id": "u-1", "role": "viewer"},
        )
    )

    key = db.alerts_table.update_item.call_args.kwargs["Key"]
    # user_id is no longer part of the schema; using it raises
    # ValidationException, which this handler would surface as a 500.
    assert key == {"origin_id": "o-mine", "alert_id": "a-1"}
    assert "user_id" not in key
