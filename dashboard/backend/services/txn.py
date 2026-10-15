"""One transaction around a change and its audit event.

    from services.txn import atomic
    with atomic():
        origin_service.update_origin(...)
        audit_log.write_audit_event(...)

PostgreSQL: db.pool.transaction() -- both commit together or neither does
(audit_log is fail-closed there). DynamoDB (legacy): a no-op context.
Only blocking DB calls belong inside: no await of external I/O, nginx reload
or file writes (statement/idle-in-transaction timeouts are 5s/10s).
"""
from contextlib import contextmanager, nullcontext


@contextmanager
def atomic():
    from services.dynamodb_service import data_backend
    if data_backend() == "postgres":
        from db import pool
        with pool.transaction():
            yield
    else:
        with nullcontext():
            yield
