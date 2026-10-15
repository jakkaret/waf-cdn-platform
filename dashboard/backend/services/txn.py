"""One transaction around a change and its audit event.

    from services.txn import atomic
    with atomic():
        origin_service.update_origin(...)
        audit_log.write_audit_event(...)

Both commit together or neither does (audit_log is fail-closed). Only
blocking DB calls belong inside: no await of external I/O, nginx reload or
file writes (the app role has statement/idle-in-transaction timeouts of
5s/10s).
"""
from db.pool import transaction as atomic  # noqa: F401
