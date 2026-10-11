"""
Scenario: 2026-09-22 (self-service onboarding wizard, overnight session) --
the wizard needs to resume at the right step if a user refreshes or comes
back later, rather than always restarting from step 1. compute_onboarding_
status() is the pure aggregation logic behind GET /api/onboarding/status;
kept separate from the DB/origin_service calls so every branch is directly
testable without needing the fake DynamoDB store wired up.
"""
import api.onboarding as onboarding


def test_a_brand_new_user_with_no_origins_is_told_to_create_one():
    status = onboarding.compute_onboarding_status(origins=[], domain_items=[])
    assert status["next_step"] == "create_origin"
    assert status["onboarding_complete"] is False


def test_an_origin_with_no_domain_attached_is_told_to_add_a_domain():
    origins = [{"id": "o1"}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=[])
    assert status["next_step"] == "add_domain"
    assert status["domain_configured"] is False


def test_an_unverified_domain_is_told_to_verify():
    origins = [{"id": "o1"}]
    domains = [{"origin_id": "o1", "domain_name": "shop.example.com", "dns_verified": False}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=domains)
    assert status["next_step"] == "verify_domain"
    assert status["domain_configured"] is True
    assert status["domain_verified"] is False


def test_a_verified_domain_completes_onboarding():
    origins = [{"id": "o1"}]
    domains = [{"origin_id": "o1", "domain_name": "myshop.waf-it-kku.online", "dns_verified": True}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=domains)
    assert status["next_step"] == "done"
    assert status["onboarding_complete"] is True


def test_a_live_tunnel_domain_counts_as_configured_and_verified_without_a_domains_table_row():
    # cloudwaf/FRP tunnel domains never get a domains_table row at all --
    # tunnel_domains on the origin itself is the only signal, and it only
    # exists once a real agent has actually connected and claimed it.
    origins = [{"id": "o1", "tunnel_domains": ["juice.waf-it-kku.online"]}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=[])
    assert status["domain_configured"] is True
    assert status["domain_verified"] is True
    assert status["next_step"] == "done"


def test_a_verified_older_origin_does_not_complete_a_new_one():
    # The bug this replaces: status was account-wide, so one verified origin
    # made every later origin read "done" and the wizard showed its success
    # screen before the new origin had a domain.
    origins = [{"id": "old", "created_at": "2026-10-01"}, {"id": "new", "created_at": "2026-10-09"}]
    domains = [{"id": "d1", "origin_id": "old", "domain_name": "old.example.com", "dns_verified": True}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=domains)
    assert status["next_step"] == "add_domain"
    assert status["resume_origin_id"] == "new"
    assert status["onboarding_complete"] is False


def test_a_tunnel_on_another_origin_does_not_complete_a_new_one():
    origins = [
        {"id": "shared", "created_at": "2026-10-01", "tunnel_domains": ["x.example.com"]},
        {"id": "new", "created_at": "2026-10-09"},
    ]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=[])
    assert status["next_step"] == "add_domain"


def test_the_newest_origin_with_an_unverified_domain_resumes_on_that_domain():
    origins = [{"id": "old", "created_at": "2026-10-01"}, {"id": "new", "created_at": "2026-10-09"}]
    domains = [
        {"id": "d1", "origin_id": "old", "domain_name": "old.example.com", "dns_verified": True},
        {"id": "d2", "origin_id": "new", "domain_name": "new.example.com", "dns_verified": False},
    ]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=domains)
    assert status["next_step"] == "verify_domain"
    assert status["resume_domain_id"] == "d2"
    assert status["resume_domain_name"] == "new.example.com"


def test_origin_count_reflects_the_real_number_of_origins():
    origins = [{"id": "o1"}, {"id": "o2"}, {"id": "o3"}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=[])
    assert status["origin_count"] == 3
    assert status["has_origin"] is True
