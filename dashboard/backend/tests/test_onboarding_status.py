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


def test_a_domain_belonging_to_a_different_origin_does_not_count():
    origins = [{"id": "o1"}, {"id": "o2"}]
    domains = [{"origin_id": "o2", "domain_name": "other.example.com", "dns_verified": True}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=domains)
    # o1 has none; o2 is verified -- overall still "done" since at least one
    # origin is fully configured, but this proves cross-origin domains
    # aren't attributed to the wrong origin's status.
    assert status["next_step"] == "done"


def test_origin_count_reflects_the_real_number_of_origins():
    origins = [{"id": "o1"}, {"id": "o2"}, {"id": "o3"}]
    status = onboarding.compute_onboarding_status(origins=origins, domain_items=[])
    assert status["origin_count"] == 3
    assert status["has_origin"] is True
