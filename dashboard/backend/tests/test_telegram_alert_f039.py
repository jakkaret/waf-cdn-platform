"""F-039: Telegram text is HTML-escaped. An unescaped attacker URL made
Telegram reject (i.e. drop) the alert, and a crafted `<a href>` could put a
link into someone's alert. Incident messages carry the site label (set by
the user) and IPs, attack types and paths (set by the attacker)."""
import datetime as dt

from services import alert_incidents as ai

T = dt.datetime(2026, 10, 23, 6, 9, tzinfo=dt.timezone.utc)
INC = {
    "incident_id": "00000000-0000-0000-0000-000000000001", "scope": "o1",
    "opened_at": T, "last_seen_at": T + dt.timedelta(minutes=5), "open_count": 315,
    "blocked_count": 315, "ip_count": 1, "domain": "shop.example.com",
    "top_ips": [["<a href=x>", 315]], "top_types": [["XSS <script>alert(1)</script>", 315]],
}


def test_incident_messages_are_html_escaped():
    for msg in (ai.format_open(INC, "<b>shop</b>"), ai.format_escalate(INC, "<b>shop</b>"),
                ai.format_close(INC, "<b>shop</b>", "AI <i>summary</i>")):
        assert "<script>" not in msg and "<a href" not in msg and "<b>shop</b>" not in msg
        assert "<i>summary</i>" not in msg
        assert "&lt;script&gt;" in msg or "&lt;a href" in msg


def test_open_message_names_the_site_first_and_drops_internal_details():
    msg = ai.format_open(INC, "shop")
    assert msg.startswith("🔴 <b>shop กำลังถูกโจมตี</b>")
    assert "โดเมน: shop.example.com" in msg
    assert "13:09" in msg  # Bangkok time
    assert "Node" not in msg and "edge" not in msg and "CRITICAL" not in msg


def test_close_message_has_duration_and_marks_ai_text_only_when_present():
    with_ai = ai.format_close(INC, "shop", "สรุป\nควรทำ: ไม่ต้องทำอะไรเพิ่ม")
    without = ai.format_close(INC, "shop", None)
    assert "13:09–13:14 น. (5 นาที)" in without
    assert "สรุปโดย AI" in with_ai and "AI" not in without


def test_ai_report_marks_become_telegram_tags_and_nothing_else():
    out = ai.report_html("- บอตหา `/.env` และ **<script>**\n- ควรทำ: ไม่ต้องทำอะไรเพิ่ม")
    assert out == "• บอตหา <code>/.env</code> และ <b>&lt;script&gt;</b>\n• ควรทำ: ไม่ต้องทำอะไรเพิ่ม"
