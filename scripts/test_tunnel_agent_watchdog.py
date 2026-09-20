"""
Scenario: Trello "tunnel agent หลุดแล้วไม่ auto-recover (watchdog)" -- frpc
(systemd unit `waf-agent` on Lab) has been observed getting stuck in a
reconnect retry-loop without recovering on its own, twice in one session,
requiring a manual restart each time.

An earlier version of this watchdog polled Main's FRP admin dashboard
(:7500) cross-machine to check health. Verified live 2026-09-20 that this
was broken by construction -- `ss -tlnp` on Main shows :7500 bound to
127.0.0.1 only (a deliberate prior security fix), so a Lab-side watchdog
could never actually reach it; it would have silently done nothing
forever. This tests the corrected design's two pure decision functions
(should_restart, all_domains_healthy) -- no network or systemctl calls, so
these run anywhere without touching the real Lab or Main.
"""
from tunnel_agent_watchdog import should_restart, all_domains_healthy


# ------------------------------------------------------------- should_restart

def test_does_not_restart_below_the_failure_threshold():
    """A single missed check (a brief blip) must not trigger a restart --
    only a sustained streak should."""
    assert should_restart(consecutive_failures=1, last_restart_ts=None, now=1000.0, failure_threshold=3) is False
    assert should_restart(consecutive_failures=2, last_restart_ts=None, now=1000.0, failure_threshold=3) is False


def test_restarts_once_the_failure_threshold_is_reached_with_no_prior_restart():
    assert should_restart(consecutive_failures=3, last_restart_ts=None, now=1000.0, failure_threshold=3) is True


def test_does_not_restart_again_within_the_cooldown_window():
    """Prevents a restart-loop when the underlying cause isn't actually
    fixed by restarting -- must wait out the cooldown even if the failure
    streak keeps climbing."""
    last_restart = 1000.0
    now = last_restart + 60  # only 1 minute after a restart
    assert should_restart(
        consecutive_failures=10, last_restart_ts=last_restart, now=now,
        failure_threshold=3, cooldown_seconds=600,
    ) is False


def test_restarts_again_once_the_cooldown_has_elapsed():
    last_restart = 1000.0
    now = last_restart + 601  # just past the 600s cooldown
    assert should_restart(
        consecutive_failures=3, last_restart_ts=last_restart, now=now,
        failure_threshold=3, cooldown_seconds=600,
    ) is True


def test_cooldown_fully_elapsed_at_exactly_the_boundary_permits_a_restart():
    """At exactly `cooldown_seconds` elapsed, the cooldown has genuinely
    finished -- this documents that as intentional (a strict `<` check
    blocks only while still inside the window), not an off-by-one bug."""
    last_restart = 1000.0
    now = last_restart + 600  # exactly at the boundary
    assert should_restart(
        consecutive_failures=3, last_restart_ts=last_restart, now=now,
        failure_threshold=3, cooldown_seconds=600,
    ) is True


# ----------------------------------------------------------- all_domains_healthy

def test_all_domains_returning_200_is_healthy():
    assert all_domains_healthy({"dvwa.example.com": 200, "juice.example.com": 200}) is True


def test_a_403_from_the_waf_itself_is_still_healthy():
    """A 403 means the tunnel is UP and the WAF answered -- this probe
    intentionally uses a cache-busting query string that could plausibly
    trip a WAF rule; that must not be mistaken for the tunnel being down."""
    assert all_domains_healthy({"dvwa.example.com": 403}) is True


def test_a_gateway_error_status_is_unhealthy():
    """502/503/504 (and Cloudflare-style 522-524) mean nginx/Caddy got a
    response back from asking for the origin, but the tunnel behind it
    didn't answer -- the actual failure mode this watchdog exists for."""
    assert all_domains_healthy({"dvwa.example.com": 200, "juice.example.com": 502}) is False


def test_a_failed_request_with_no_status_code_is_unhealthy():
    """None means the HTTPS request itself never completed (timeout,
    connection refused, DNS failure) -- must count as unhealthy, not be
    silently ignored."""
    assert all_domains_healthy({"dvwa.example.com": None}) is False


def test_empty_results_is_vacuously_healthy():
    """No watched domains configured -- nothing to be unhealthy about.
    (WATCHED_DOMAINS being non-empty is a deployment-config concern, not
    this function's.)"""
    assert all_domains_healthy({}) is True
