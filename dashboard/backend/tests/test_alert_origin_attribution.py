"""
Scenario: an alert is scoped by the origin it actually belongs to, not by
a substring match on its Host header.

waf_alerts is keyed (user_id, alert_id) where user_id is the constant
"default-user", so the key says nothing about ownership and isolation has
to happen at read time. The 2026-09-22 fix matched the captured Host
against the tenant's registered domains with a two-way substring test,
which is loose in a way that matters: a tenant registered for
"example.com" matches an alert whose Host was
"example.com.attacker.test", because one string contains the other.

Alerts now carry an origin_id resolved once at write time through
waf_domains' domain_name-index. These tests pin that exact attribution
wins, that an unattributable alert is not handed to a guessed owner, and
that pre-existing rows keep working via the old path.
"""
from unittest.mock import MagicMock

import pytest

import api.ai_summary as ai_summary_module


@pytest.fixture()
def visible(monkeypatch):
    """Call _visible_alerts_for_user with a given alert set and scope."""

    def _run(alerts, origin_ids, user_domains, role="viewer"):
        fake_db = MagicMock()
        # Post-migration read path: alerts carrying an origin_id come back
        # from a per-partition query, and only rows with no origin_id (the
        # pre-migration tail) are reached by the scan.
        fake_db.get_all_alerts.return_value = alerts
        fake_db.get_alerts_for_origins.side_effect = lambda oids, max_items=2000: [
            a for a in alerts if str(a.get("origin_id") or "") in set(oids)
        ]
        monkeypatch.setattr(ai_summary_module, "db", fake_db)
        monkeypatch.setattr(
            ai_summary_module,
            "get_user_origins_and_domains",
            lambda _uid: (origin_ids, [], user_domains),
        )
        return ai_summary_module._visible_alerts_for_user(
            {"user_id": "u-1", "role": role}
        )

    return _run


def test_lookalike_domain_no_longer_leaks_across_tenants(visible):
    # The exact case the substring match got wrong: the attacker-controlled
    # Host merely *contains* the victim's registered domain.
    alerts = [
        {"alert_id": "a-mine", "origin_id": "o-mine", "domain": "example.com"},
        {"alert_id": "a-lookalike", "origin_id": "o-other", "domain": "example.com.attacker.test"},
    ]
    got = visible(alerts, origin_ids=["o-mine"], user_domains=["example.com"])
    assert [a["alert_id"] for a in got] == ["a-mine"]


def test_alert_for_another_origin_is_not_visible(visible):
    alerts = [{"alert_id": "a-1", "origin_id": "o-theirs", "domain": "theirs.example.com"}]
    assert visible(alerts, origin_ids=["o-mine"], user_domains=["mine.example.com"]) == []


def test_granted_origin_alerts_are_visible(visible):
    # origin_ids comes from get_origins_visible_to_user, so a viewer grant
    # has to carry through to alerts as well as to logs and analytics.
    alerts = [{"alert_id": "a-shared", "origin_id": "o-granted", "domain": "shared.example.com"}]
    got = visible(alerts, origin_ids=["o-owned", "o-granted"], user_domains=["owned.example.com"])
    assert [a["alert_id"] for a in got] == ["a-shared"]


def test_unattributable_alert_is_not_shown_to_a_guessed_owner(visible):
    # Host was not a registered domain (direct-to-IP hit, or a probe for
    # someone else's hostname): origin_id is "" and there is no domain to
    # fall back on, so it must not surface for a non-admin.
    alerts = [{"alert_id": "a-orphan", "origin_id": "", "domain": ""}]
    assert visible(alerts, origin_ids=["o-mine"], user_domains=["mine.example.com"]) == []


def test_legacy_alert_without_origin_id_still_matches_by_domain(visible):
    # Rows written before origin_id existed. The Host was all that was
    # captured, so the old match is the only thing available for them.
    alerts = [{"alert_id": "a-old", "domain": "mine.example.com"}]
    got = visible(alerts, origin_ids=["o-mine"], user_domains=["mine.example.com"])
    assert [a["alert_id"] for a in got] == ["a-old"]


def test_admin_still_sees_everything(visible):
    alerts = [
        {"alert_id": "a-1", "origin_id": "o-a"},
        {"alert_id": "a-2", "origin_id": ""},
    ]
    got = visible(alerts, origin_ids=[], user_domains=[], role="admin")
    assert len(got) == 2


def test_user_with_no_origins_and_no_domains_sees_nothing(visible):
    alerts = [{"alert_id": "a-1", "origin_id": "o-a", "domain": "a.example.com"}]
    assert visible(alerts, origin_ids=[], user_domains=[]) == []
