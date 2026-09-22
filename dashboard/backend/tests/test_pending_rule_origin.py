"""
Scenario: a pending ML/CVE rule records which origin's exposure produced
it, instead of floating free of the data model.

waf_pending_rules is keyed (rule_id, created_at) with a status-index and
carried no origin reference at all, so nothing in the queue could say
whose problem a proposal was. That is part of why the endpoints had to
be locked to admin outright (b414134) -- there was no field to scope on.

The CVE scanner does know: cve_feed.match_cves_to_origins() matches a
CVE's keywords against one specific origin's tech_stack_tags. The ML
anomaly path genuinely does not -- /api/ml/analyze takes url/method/body
with no Host -- so these tests also pin that it stores an empty value
rather than inventing one.

Attribution does not make the queue per-tenant: approving a rule deploys
it to ModSecurity for every origin. The admin-only gate is unchanged and
asserted in test_ml_rules_access_scope.py.

MLRuleService binds DynamoDBService and RuleManager into its own module
namespace at import, so conftest's fake_infrastructure (which patches the
class at services.dynamodb_service) does not reach it, and constructing
it for real would touch the live waf_pending_rules table, write
ModSecurity conf files and reload nginx -- the same reason
test_ml_rules_audit.py mocks the service wholesale. Both collaborators
are therefore patched here in ml_rule_service's own namespace.
"""
from unittest.mock import MagicMock

import pytest

import services.ml_rule_service as ml_rule_service_module
from services.ml_rule_service import MLRuleService


class _FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(dict(Item))

    def query(self, KeyConditionExpression=None, **_kwargs):
        # get_rule_detail() queries by the rule_id partition key; the fake
        # keeps every written item and filters on the value the condition
        # was built with.
        wanted = getattr(KeyConditionExpression, "_values", (None, None))[1]
        return {"Items": [i for i in self.items if i.get("rule_id") == wanted]}


@pytest.fixture()
def service(monkeypatch):
    table = _FakeTable()
    fake_db = MagicMock()
    fake_db.dynamodb.Table.return_value = table
    monkeypatch.setattr(ml_rule_service_module, "DynamoDBService", lambda: fake_db)
    monkeypatch.setattr(ml_rule_service_module, "RuleManager", MagicMock())
    return MLRuleService()


def test_cve_proposal_records_the_matched_origin(service):
    item = service.create_pending_rule(
        {
            "pattern": "@rx evil",
            "attack_type": "CVE Virtual Patch (CVE-2026-1234)",
            "cve_id": "CVE-2026-1234",
            "origin_id": "origin-abc",
            "origin_label": "shop (shop.example.com)",
        },
        created_by="cve-auto",
    )
    assert item["origin_id"] == "origin-abc"
    assert item["origin_label"] == "shop (shop.example.com)"


def test_anomaly_proposal_without_origin_context_stores_empty_not_a_guess(service):
    item = service.create_pending_rule(
        {"pattern": "@rx anomaly", "attack_type": "Anomaly Pattern"},
        created_by="ml-auto",
    )
    # Empty means "not attributable". A placeholder origin id here would
    # read as a real attribution to whoever happened to be named.
    assert item["origin_id"] == ""
    assert item["origin_label"] == ""


def test_origin_attribution_is_persisted_not_just_returned(service):
    created = service.create_pending_rule(
        {"pattern": "@rx x", "origin_id": "origin-xyz"}, created_by="cve-auto"
    )
    fetched = service.get_rule_detail(created["rule_id"])
    assert fetched is not None
    assert fetched["origin_id"] == "origin-xyz"
