"""Map PostgreSQL constraint errors to ValueError, so handlers that already
turn ValueError into HTTP 400 (e.g. api/auth.py register) keep working.
Messages never expose internal constraint names."""
from __future__ import annotations

import psycopg
from psycopg import errors as pg_errors


class ConstraintError(ValueError):
    """A CHECK / NOT NULL / UNIQUE / FOREIGN KEY constraint refused a write.
    `constraint` keeps the name for logs and for callers that branch on it."""

    def __init__(self, message: str, constraint: str = ""):
        super().__init__(message)
        self.constraint = constraint


class UniqueConflict(ConstraintError):
    pass


class ForeignKeyConflict(ConstraintError):
    pass


def translate(exc: psycopg.Error) -> Exception:
    diag = getattr(exc, "diag", None)
    name = (getattr(diag, "constraint_name", None) or "") if diag else ""
    if isinstance(exc, pg_errors.UniqueViolation):
        return UniqueConflict("already exists", name)
    if isinstance(exc, pg_errors.ForeignKeyViolation):
        return ForeignKeyConflict("referenced row missing or still in use", name)
    if isinstance(exc, (pg_errors.CheckViolation, pg_errors.NotNullViolation)):
        return ConstraintError("invalid value", name)
    return exc
