"""Times people type into the AI summary and postmortem forms are Bangkok
time; ClickHouse and PostgreSQL hold UTC (api/ai_summary.py)."""
from datetime import datetime, timezone

from api import ai_summary as ai


def test_typed_bounds_are_bangkok_and_queries_get_utc():
    assert ai._parse_time_bound("2026-10-25 07:00:00", "start_time") == datetime(2026, 10, 25, 0, 0)
    assert ai._parse_time_bound("2026-10-25", "start_time") == datetime(2026, 10, 24, 17, 0)
    aware = datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc)
    assert ai._parse_time_bound(aware, "start_time") == datetime(2026, 10, 25, 0, 0)


def test_ranges_are_shown_in_bangkok_time():
    start, end = datetime(2026, 10, 25, 0, 0), datetime(2026, 10, 25, 6, 0)  # UTC
    assert ai._describe_range(start, end) == "2026-10-25 07:00 ถึง 2026-10-25 13:00 เวลาไทย (6 ชั่วโมง)"
    assert ai._bkk_text(datetime(2026, 10, 24, 20, 0)) == "2026-10-25 03:00:00"


def test_postmortem_timeline_is_shown_in_bangkok_time():
    timeline = {
        "start_time": "2026-10-25 00:00:00", "end_time": "2026-10-25 06:00:00",
        "hourly_buckets": [{"hour": "2026-10-25 03:00:00", "requests": 5, "alerts": 1}],
        "audit_events": [{"action": "settings.update", "timestamp": "2026-10-25T03:11:00+00:00"}],
        "stats": {},
    }
    shown = ai._timeline_in_bangkok(timeline, datetime(2026, 10, 25, 0, 0), datetime(2026, 10, 25, 6, 0))
    assert shown["start_time"] == "2026-10-25 07:00:00" and shown["end_time"] == "2026-10-25 13:00:00"
    assert shown["hourly_buckets"][0]["hour"] == "2026-10-25 10:00:00"
    assert shown["audit_events"][0]["timestamp"] == "2026-10-25T10:11:00+07:00"
    assert timeline["hourly_buckets"][0]["hour"] == "2026-10-25 03:00:00"  # the UTC original is untouched
