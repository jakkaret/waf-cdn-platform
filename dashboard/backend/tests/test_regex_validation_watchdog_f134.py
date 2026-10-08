"""F-134: rule-save regex validation must not reject a legitimate pattern just
because process start-up/scheduling exceeded a 30 ms watchdog on a busy host,
while genuinely catastrophic patterns are still rejected."""
import services.safe_regex as sr


def test_validation_watchdog_tolerates_slow_worker_startup(monkeypatch):
    seen = []
    real = sr.run_isolated_regex

    def spy(pattern, text, timeout_sec=0.03, mode="search"):
        seen.append(timeout_sec)
        return real(pattern, text, timeout_sec=timeout_sec, mode=mode)

    monkeypatch.setattr(sr, "run_isolated_regex", spy)
    ok, reason = sr.validate_regex_safety(r"^/api/v1/users/\d+$")
    assert ok, reason
    assert seen and min(seen) >= 0.5


def test_simulated_slow_start_does_not_reject_a_simple_pattern(monkeypatch):
    # A worker that finishes the match instantly but only reports back after
    # 80 ms (slow fork/scheduling) used to time out at 30 ms.
    def slow_start(pattern, text, timeout_sec=0.03, mode="search"):
        return (True, 0.08 > timeout_sec, 0.0001)

    monkeypatch.setattr(sr, "run_isolated_regex", slow_start)
    ok, reason = sr.validate_regex_safety(r"admin|login")
    assert ok, reason


def test_catastrophic_pattern_still_rejected():
    ok, _ = sr.validate_regex_safety(r"(a+)+$")
    assert not ok
