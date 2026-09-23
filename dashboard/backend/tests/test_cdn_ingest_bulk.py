"""
Scenario: the edge log forwarder can actually drain its buffer, and a
blocked request coming through an edge produces the same alert a blocked
request on Main's own nginx does.

Found live 2026-09-23 on edge-th: every POST to /api/cdn/logs/ingest hit
the forwarder's 5s client timeout, so nothing was ever acknowledged, the
buffer grew (4679 entries and climbing), and each retry sent a *larger*
batch than the one that had just timed out. api/cdn.py's own docstring
records the reason a single entry could take ~5.9s: one ClickHouse insert
plus one DynamoDB PutItem, per entry, each a separate round trip.

These tests pin the property that makes a backlog drainable: the number
of store calls must not scale with the number of entries in the batch.
They deliberately assert on call counts rather than on wall-clock time --
timing assertions would pass or fail on whatever else the machine is
doing, while "one insert for the whole batch" is the actual invariant.

Found the same day, verified live against www.originweb.site (a real
tunnel origin behind edge-th): dispatch_telegram_alert was imported here
from the start and never called from this path. Two 403s landed in
access_logs with alert=1 and zero rows appeared in waf_alerts_v2 -- every
blocked request through an edge (most real traffic) was invisible on the
Alert Center page and sent no Telegram push. _store_cdn_log_batch now
returns which normalized entries meet the same alert condition
log_forward.py's try_merge/flush_old_logs use, and the async endpoint
dispatches them -- it has to be the endpoint, not this function: this
function runs inside asyncio.to_thread (a worker thread, no running event
loop), so asyncio.create_task() cannot be called from here.
"""
import asyncio

import api.cdn as cdn_module


class _RecordingClickHouse:
    def __init__(self):
        self.connected = True
        self.bulk_calls = []
        self.single_calls = 0

    def save_logs_bulk(self, table_name, entries):
        self.bulk_calls.append((table_name, len(entries)))
        return len(entries)

    def save_log(self, table_name, data):
        self.single_calls += 1
        return True


class _RecordingDynamo:
    def __init__(self):
        self.bulk_calls = []
        self.single_calls = 0

    def save_logs_bulk(self, events):
        self.bulk_calls.append(len(events))
        return len(events)

    def save_log(self, event):
        self.single_calls += 1


def _entries(n, status="200"):
    return [
        {
            "request_id": f"req-{i}",
            "remote_addr": "203.0.113.5",
            "method": "GET",
            "request_uri": f"/page/{i}",
            "status": status,
            "host": "dvwa.waf-it-kku.online",
        }
        for i in range(n)
    ]


def test_batch_is_stored_in_one_call_per_store(monkeypatch):
    ch, db = _RecordingClickHouse(), _RecordingDynamo()
    monkeypatch.setattr(cdn_module, "ch", ch)
    monkeypatch.setattr(cdn_module, "_db", db)

    stored, flagged = cdn_module._store_cdn_log_batch(_entries(120), "th")

    assert stored == 120
    assert flagged == []  # all status 200, nothing alert-worthy
    # The invariant: round trips stay constant as the batch grows. A
    # 4679-entry backlog is only drainable if this stays 1.
    assert ch.bulk_calls == [("access_logs", 120)]
    assert ch.single_calls == 0, "per-entry insert is what wedged the pipeline"
    # waf_logs is keyed (constant user_id, whole-second timestamp), so it
    # could never hold more than one row per second and a real batch is
    # rejected outright for duplicate keys. Nothing may write there.
    assert db.bulk_calls == []
    assert db.single_calls == 0


def test_host_survives_into_the_stored_rows(monkeypatch):
    # The edge's cdn_json log_format gained "host":"$host" in the same
    # change; normalize_cdn_access has to carry it through, otherwise edge
    # traffic keeps falling back to URL-keyword tenant attribution.
    captured = {}

    class _CapturingClickHouse(_RecordingClickHouse):
        def save_logs_bulk(self, table_name, entries):
            captured["rows"] = entries
            return len(entries)

    monkeypatch.setattr(cdn_module, "ch", _CapturingClickHouse())
    monkeypatch.setattr(cdn_module, "_db", _RecordingDynamo())

    cdn_module._store_cdn_log_batch(_entries(3), "th")

    assert [r["host"] for r in captured["rows"]] == ["dvwa.waf-it-kku.online"] * 3


def test_unparseable_entry_does_not_lose_the_rest_of_the_batch(monkeypatch):
    ch, db = _RecordingClickHouse(), _RecordingDynamo()
    monkeypatch.setattr(cdn_module, "ch", ch)
    monkeypatch.setattr(cdn_module, "_db", db)

    def _explode(entry, region):
        if entry.get("request_id") == "req-1":
            raise ValueError("malformed")
        return dict(entry)

    monkeypatch.setattr(cdn_module, "normalize_cdn_access", _explode)

    stored, _flagged = cdn_module._store_cdn_log_batch(_entries(3), "th")

    # One bad entry is dropped and reported; the other two still land.
    assert stored == 2
    assert ch.bulk_calls == [("access_logs", 2)]


def test_empty_batch_touches_neither_store(monkeypatch):
    ch, db = _RecordingClickHouse(), _RecordingDynamo()
    monkeypatch.setattr(cdn_module, "ch", ch)
    monkeypatch.setattr(cdn_module, "_db", db)

    assert cdn_module._store_cdn_log_batch([], "th") == (0, [])
    assert ch.bulk_calls == []
    assert db.bulk_calls == []


# --- alert dispatch -----------------------------------------------------


def test_blocked_entry_is_flagged_for_dispatch(monkeypatch):
    monkeypatch.setattr(cdn_module, "ch", _RecordingClickHouse())
    monkeypatch.setattr(cdn_module, "_db", _RecordingDynamo())

    _stored, flagged = cdn_module._store_cdn_log_batch(_entries(1, status="403"), "th")

    assert len(flagged) == 1
    assert flagged[0]["status"] == 403


def test_rate_limited_entry_is_flagged_too(monkeypatch):
    monkeypatch.setattr(cdn_module, "ch", _RecordingClickHouse())
    monkeypatch.setattr(cdn_module, "_db", _RecordingDynamo())

    _stored, flagged = cdn_module._store_cdn_log_batch(_entries(1, status="429"), "th")

    assert len(flagged) == 1


def test_ok_entries_are_never_flagged(monkeypatch):
    monkeypatch.setattr(cdn_module, "ch", _RecordingClickHouse())
    monkeypatch.setattr(cdn_module, "_db", _RecordingDynamo())

    _stored, flagged = cdn_module._store_cdn_log_batch(_entries(50, status="200"), "th")

    assert flagged == []


def test_ingest_endpoint_dispatches_one_alert_per_flagged_entry(monkeypatch):
    # The endpoint, not _store_cdn_log_batch, must do the dispatching:
    # _store_cdn_log_batch runs inside asyncio.to_thread (a worker thread
    # with no running event loop), so asyncio.create_task() cannot be
    # called from there -- it would raise "no running event loop". This
    # test would fail loudly if dispatch were ever moved back into that
    # synchronous function.
    monkeypatch.setattr(cdn_module, "ch", _RecordingClickHouse())
    monkeypatch.setattr(cdn_module, "_db", _RecordingDynamo())

    dispatched = []

    async def _fake_dispatch(entry):
        dispatched.append(entry)

    monkeypatch.setattr(cdn_module, "dispatch_telegram_alert", _fake_dispatch)
    monkeypatch.setattr(
        cdn_module, "_KNOWN_EDGE_FORWARDER_IPS", {"203.0.113.9"}
    )

    class _FakeClient:
        host = "203.0.113.9"

    class _FakeRequest:
        client = _FakeClient()

    payload = cdn_module.CdnLogIngestPayload(
        region="th",
        logs=_entries(2, status="403") + _entries(1, status="200"),
    )

    async def _run():
        return await cdn_module.ingest_cdn_logs(payload, _FakeRequest())

    result = asyncio.run(_run())

    assert result["stored"] == 3
    assert len(dispatched) == 2
    assert all(e["status"] == 403 for e in dispatched)
