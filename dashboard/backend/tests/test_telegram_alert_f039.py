"""F-039: Telegram alert text is HTML-escaped (an unescaped attacker URL made
Telegram reject, i.e. drop, the alert) and repeat pushes are rate-limited per
(origin, client IP, rule)."""
import services.telegram_listener as tl


def test_alert_message_is_html_escaped():
    msg = tl._format_alert_message("403", "edge-th", "203.0.113.10",
                                   "/?q=<script>alert(1)</script>&a=<a href=x>", "941100",
                                   "CRITICAL", "XSS", "AI <b>summary</b>", "now")
    assert "<script>" not in msg and "<a href" not in msg and "<b>summary</b>" not in msg
    assert "&lt;script&gt;" in msg
    assert msg.startswith("🚨 <b>WAF SECURITY ALERT (403)</b>")  # our own markup intact


def test_telegram_cooldown_per_origin_ip_rule(monkeypatch):
    monkeypatch.setattr(tl, "_last_push", {})
    key = ("o1", "203.0.113.10", "942100")
    assert tl._telegram_cooldown_ok(key, 1000.0) is True
    assert tl._telegram_cooldown_ok(key, 1000.0 + 10) is False
    assert tl._telegram_cooldown_ok(("o1", "203.0.113.11", "942100"), 1010.0) is True
    assert tl._telegram_cooldown_ok(key, 1000.0 + tl.TELEGRAM_COOLDOWN_SECONDS + 1) is True
