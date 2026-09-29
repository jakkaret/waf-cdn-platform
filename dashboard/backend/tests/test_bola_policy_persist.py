"""services/bola_guard.py used time.time() without importing time, so saving a
BOLA policy to DynamoDB always raised NameError -- swallowed by a debug-level
log -- and every policy vanished on restart."""
from unittest.mock import MagicMock

import services.bola_guard as bola_guard_module


def test_persist_policy_writes_to_dynamodb(monkeypatch):
    fake_db = MagicMock()
    import services.dynamodb_service as dynamodb_service_module
    monkeypatch.setattr(dynamodb_service_module, "DynamoDBService", lambda: fake_db)
    guard = bola_guard_module.bola_guard
    persist = getattr(guard, "_persist_policy", None)
    assert persist is not None, "expected BOLAGuard._persist_policy"
    policy = {"id": "p1", "name": "n", "path_pattern": "/api/users/{id}", "claim_key": "sub",
              "resource_type": "user_id", "action": "BLOCK", "allow_admin": True, "description": ""}
    persist(policy)
    assert fake_db.rules_table.put_item.called, "policy was not written (NameError swallowed?)"
