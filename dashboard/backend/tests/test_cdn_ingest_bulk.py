"""
Scenario: the edge log forwarder can actually drain its buffer.

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
"""
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


def _entries(n):
    return [
        {
            "request_id": f"req-{i}",
            "remote_addr": "203.0.113.5",
            "method": "GET",
            "request_uri": f"/page/{i}",
            "status": "200",
            "host": "dvwa.waf-it-kku.online",
        }
        for i in range(n)
    ]


def test_batch_is_stored_in_one_call_per_store(monkeypatch):
    ch, db = _RecordingClickHouse(), _RecordingDynamo()
    monkeypatch.setattr(cdn_module, "ch", ch)
    monkeypatch.setattr(cdn_module, "_db", db)

    stored = cdn_module._store_cdn_log_batch(_entries(120), "th")

    assert stored == 120
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

    stored = cdn_module._store_cdn_log_batch(_entries(3), "th")

    # One bad entry is dropped and reported; the other two still land.
    assert stored == 2
    assert ch.bulk_calls == [("access_logs", 2)]


def test_empty_batch_touches_neither_store(monkeypatch):
    ch, db = _RecordingClickHouse(), _RecordingDynamo()
    monkeypatch.setattr(cdn_module, "ch", ch)
    monkeypatch.setattr(cdn_module, "_db", db)

    assert cdn_module._store_cdn_log_batch([], "th") == 0
    assert ch.bulk_calls == []
    assert db.bulk_calls == []
