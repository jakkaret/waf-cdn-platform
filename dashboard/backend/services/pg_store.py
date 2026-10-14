"""PostgreSQL implementation of the control-plane store (schema `waf`).

Selected with DATA_BACKEND=postgres: services/dynamodb_service.py then
exports PgStore under the old DynamoDBService name, so the 26+ modules that
import it need no change.

Method groups move here phase by phase (migration plan Phases 3-5). Until a
group is implemented it is inherited from the DynamoDB-backed store, which in
production fails exactly as it did before the switch. That base class is
removed in Phase 7, once every method is SQL.

__init__ does no I/O: modules build this at import time.
"""
from __future__ import annotations

from db import pool
from services.dynamodb_service import _DynamoBackedStore


class PgStore(_DynamoBackedStore):
    backend = "postgres"

    def __init__(self):
        # The inherited (not yet converted) methods need the boto3 table
        # handles; building them is local object construction, not I/O.
        super().__init__()

    def ping(self) -> bool:
        """Reachability probe for /api/system/status (raises on failure)."""
        if not pool.ping(timeout=1.0):
            raise ConnectionError("PostgreSQL unreachable")
        return True
