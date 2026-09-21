"""build_incident_timeline is the actual feature (2026-09-22, AI Incident
Postmortem): a mediocre prompt over a correct timeline is still useful, but
a great prompt over a wrong timeline is not. This is pure assembly -- no
Gemini call -- so every case here is a plain function test.

The scope trap this guards against: settings.update and rule.approve/reject
are written with scope_id="global" (system-wide), while origin.update /
domain.create / editor.grant etc. are written with scope_id=<origin_id>. A
postmortem that only reads the origin-scoped log would silently miss every
system-settings change -- including the exact worked example the concept
card describes (a paranoia_level change causing a false-positive spike)."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from api import ai_summary as ai_summary_module
from api.ai_summary import build_incident_timeline
import services.audit_log as audit_log_module


@pytest.fixture(autouse=True)
def _patch_audit_log_db(monkeypatch, fake_infrastructure):
    from tests.conftest import FakeDynamoDBService, _STORE
    _STORE["waf_audit_log"] = []
    monkeypatch.setattr(audit_log_module, "db", FakeDynamoDBService())


def _origin(origin_id="origin-1", ip="203.0.113.9"):
    return {"id": origin_id, "ip": ip, "label": "test-origin"}


def test_timeline_correlates_a_global_settings_change_with_an_origin_scoped_alert_spike(monkeypatch):
    start = datetime(2026, 9, 22, 3, 0, 0)
    end = datetime(2026, 9, 22, 4, 0, 0)

    # The exact worked example: an admin's global settings.update at 03:11,
    # then an alert spike in the 03:00 hourly bucket.
    audit_log_module.write_audit_event(
        scope_id="global", actor_user_id="admin-1", actor_username="admin_x",
        action="settings.update", summary="แก้ system settings: paranoia_level",
        details={"paranoia_level": {"old": 1, "new": 3}},
        now=datetime(2026, 9, 22, 3, 11, 0, tzinfo=timezone.utc),
    )
    # An origin-scoped event in the same window, to prove both scopes merge.
    audit_log_module.write_audit_event(
        scope_id="origin-1", actor_user_id="owner-1", actor_username="owner_x",
        action="origin.update", summary="แก้ origin: label",
        details={"label": {"old": "a", "new": "b"}},
        now=datetime(2026, 9, 22, 3, 5, 0, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(ai_summary_module.ch, "connected", True)
    query_spy = MagicMock()
    count_result = MagicMock(result_rows=[(840, 820)])
    type_result = MagicMock(result_rows=[("SQLi", 500)])
    bucket_result = MagicMock(result_rows=[(datetime(2026, 9, 22, 3, 0, 0), 840, 820)])
    query_spy.side_effect = [count_result, type_result, bucket_result]
    monkeypatch.setattr(ai_summary_module.ch, "client", MagicMock(query=query_spy))

    timeline = build_incident_timeline(_origin(), start, end)

    assert timeline["stats"]["total_requests"] == 840
    assert timeline["stats"]["total_alerts"] == 820
    assert timeline["hourly_buckets"][0]["alerts"] == 820

    actions = [e["action"] for e in timeline["audit_events"]]
    assert "settings.update" in actions
    assert "origin.update" in actions

    scopes = {e["action"]: e["scope"] for e in timeline["audit_events"]}
    assert scopes["settings.update"] == "global"
    assert scopes["origin.update"] == "origin"

    # Chronological order: origin.update (03:05) before settings.update (03:11).
    timestamps = [e["timestamp"] for e in timeline["audit_events"]]
    assert timestamps == sorted(timestamps)
    assert timeline["audit_events"][0]["action"] == "origin.update"
    assert timeline["audit_events"][1]["action"] == "settings.update"

    # The correlation itself: the settings.update at 03:11 falls inside the
    # same hour (03:00-04:00) as the spiked bucket -- exactly the temporal
    # relationship that makes it a root-cause candidate rather than an
    # unrelated coincidence in a report covering a wider window.
    settings_event = next(e for e in timeline["audit_events"] if e["action"] == "settings.update")
    spike_bucket_hour = timeline["hourly_buckets"][0]["hour"]  # "2026-09-22 03:00:00"
    event_dt = datetime.fromisoformat(settings_event["timestamp"])
    bucket_dt = datetime.strptime(spike_bucket_hour, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert bucket_dt <= event_dt < bucket_dt + timedelta(hours=1)


def test_timeline_excludes_audit_events_outside_the_requested_window():
    start = datetime(2026, 9, 22, 3, 0, 0)
    end = datetime(2026, 9, 22, 4, 0, 0)

    audit_log_module.write_audit_event(
        scope_id="global", actor_user_id="u", actor_username="a",
        action="settings.update", summary="before window",
        now=datetime(2026, 9, 22, 2, 0, 0, tzinfo=timezone.utc),
    )
    audit_log_module.write_audit_event(
        scope_id="global", actor_user_id="u", actor_username="a",
        action="settings.update", summary="inside window",
        now=datetime(2026, 9, 22, 3, 30, 0, tzinfo=timezone.utc),
    )
    audit_log_module.write_audit_event(
        scope_id="global", actor_user_id="u", actor_username="a",
        action="settings.update", summary="after window",
        now=datetime(2026, 9, 22, 5, 0, 0, tzinfo=timezone.utc),
    )

    timeline = build_incident_timeline(_origin(), start, end)

    summaries = [e["summary"] for e in timeline["audit_events"]]
    assert summaries == ["inside window"]


def test_timeline_is_empty_and_zeroed_when_clickhouse_is_not_connected(monkeypatch):
    monkeypatch.setattr(ai_summary_module.ch, "connected", False)
    start = datetime(2026, 9, 22, 3, 0, 0)
    end = datetime(2026, 9, 22, 4, 0, 0)

    timeline = build_incident_timeline(_origin(), start, end)

    assert timeline["stats"]["total_requests"] == 0
    assert timeline["stats"]["total_alerts"] == 0
    assert timeline["hourly_buckets"] == []
    assert timeline["audit_events"] == []
