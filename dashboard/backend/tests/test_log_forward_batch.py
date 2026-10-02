"""Main's own log tailer must never store logs on the event loop.

2026-10-02: a burst of blocked bot traffic made flush_old_logs() call the
synchronous ClickHouse + DynamoDB writes once per request on the event loop;
the API on :8000 stopped answering (1740 sockets in CLOSE-WAIT, dashboard
502). Logs now queue up and are stored as one bulk insert per drain, in a
worker thread, and alerts are still dispatched for blocked requests."""
import asyncio
import threading

import services.log_forward as lf


class _RecordingClickHouse:
    connected = True

    def __init__(self):
        self.bulk_calls = []
        self.threads = []

    def save_logs_bulk(self, table, entries):
        self.bulk_calls.append((table, len(entries)))
        self.threads.append(threading.current_thread() is threading.main_thread())
        return len(entries)

    def save_log(self, *a, **k):
        raise AssertionError("per-row save must not be used")


def _drain_once(monkeypatch):
    sleeps = {"n": 0}

    async def stop_after_first_tick(_):
        sleeps["n"] += 1
        raise asyncio.CancelledError

    monkeypatch.setattr(lf.asyncio, "sleep", stop_after_first_tick)

    async def run():
        try:
            await lf.flush_old_logs()
        except asyncio.CancelledError:
            pass
        await asyncio.gather(*[t for t in asyncio.all_tasks() if t is not asyncio.current_task()], return_exceptions=True)

    asyncio.run(run())


def test_merged_and_expired_entries_are_stored_in_one_bulk_insert_off_the_loop(monkeypatch):
    ch = _RecordingClickHouse()
    alerts = []

    async def fake_alert(data):
        alerts.append(data["request_id"])

    monkeypatch.setattr(lf, "ch", ch)
    monkeypatch.setattr(lf, "dispatch_telegram_alert", fake_alert)
    lf.log_buffer.clear()
    lf._ready.clear()

    # three complete (access + modsec) requests merge immediately ...
    for i in range(3):
        key = f"req-{i}"
        lf.log_buffer[key] = {"ts": 0, "access": {"request_id": key, "status": 200},
                              "modsec": {"request_id": key, "status": 403 if i == 0 else 200}}
        lf.try_merge(key)
    # ... and one access-only request times out into the fallback path
    lf.log_buffer["req-old"] = {"ts": 0, "access": {"request_id": "req-old", "status": 429}}

    assert ch.bulk_calls == [], "try_merge must queue, not store"
    _drain_once(monkeypatch)

    assert ch.bulk_calls == [("access_logs", 4)]
    assert ch.threads == [False], "the insert must run in a worker thread"
    assert sorted(alerts) == ["req-0", "req-old"]
    assert lf.log_buffer == {} and lf._ready == []
