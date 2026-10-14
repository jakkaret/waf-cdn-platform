"""PostgreSQL connection pool and transactions for the control-plane.

One psycopg_pool.ConnectionPool per process. Creating it does no I/O: it is
built lazily and opened on first use (or warmed in main.py's startup), so
modules that build service singletons at import time never need a database.

    from db.pool import transaction, q, q1, exec_
    row = q1("SELECT * FROM users WHERE user_id = %s", (uid,))
    with transaction():            # nested use becomes a savepoint
        exec_("UPDATE ...")
        exec_("INSERT INTO audit_logs ...")   # same transaction: fail-closed

Rules:
- Never await external I/O (NVD, Gemini, DNS, HTTP/TLS probes), reload nginx
  or write files while transaction() is open: the app role runs with
  statement_timeout=5s and idle_in_transaction_session_timeout=10s. Do that
  work before opening or after commit, and record failures with an audit
  event. Only if truly unavoidable use SET LOCAL
  idle_in_transaction_session_timeout inside that one transaction.
- The connection of an open transaction travels in a contextvar. That does
  not cross loop.run_in_executor (wrap with contextvars.copy_context().run)
  and is not shared with other threads: keep a transaction and its
  statements on one thread.

Env: DATABASE_URL (app role), PG_POOL_MIN (2), PG_POOL_MAX (12).
"""
from __future__ import annotations

import atexit
import contextvars
import os
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Sequence

import psycopg
from dotenv import find_dotenv, load_dotenv
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from db.errors import translate

# Replaces the import-time side effect services/dynamodb_service.py had:
# scripts and workers started outside dashboard/backend still find the
# project root .env.
load_dotenv(find_dotenv())
load_dotenv(os.path.join(os.path.dirname(__file__), "../../../.env"))

Params = Optional[Sequence[Any] | dict]

_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()
_current_conn: contextvars.ContextVar = contextvars.ContextVar("pg_current_conn", default=None)


class DatabaseNotConfigured(RuntimeError):
    pass


def _configure(conn: psycopg.Connection) -> None:
    # uuid columns come back as str, the shape every caller already uses.
    conn.adapters.register_loader("uuid", psycopg.types.string.TextLoader)


def get_pool() -> ConnectionPool:
    """The process pool; created (closed) on first call, opened on first use."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                dsn = os.getenv("DATABASE_URL", "").strip()
                if not dsn:
                    raise DatabaseNotConfigured("DATABASE_URL is not set")
                _pool = ConnectionPool(
                    conninfo=dsn,
                    min_size=int(os.getenv("PG_POOL_MIN", "2")),
                    max_size=int(os.getenv("PG_POOL_MAX", "12")),
                    timeout=5,
                    max_idle=300,
                    kwargs={"row_factory": dict_row, "autocommit": True, "connect_timeout": 3},
                    configure=_configure,
                    check=ConnectionPool.check_connection,
                    name="waf",
                    open=False,
                )
    return _pool


def _opened() -> ConnectionPool:
    pool = get_pool()
    if pool.closed:
        with _pool_lock:
            if pool.closed:
                pool.open(wait=False)
                # Close the pool's worker threads before interpreter
                # shutdown (one-shot scripts otherwise warn at exit).
                atexit.register(close_pool)
    return pool


def open_pool(timeout: float = 10.0) -> None:
    """Warm the pool at startup (main.py); waits for min_size connections."""
    pool = get_pool()
    if pool.closed:
        pool.open(wait=True, timeout=timeout)
        atexit.register(close_pool)


def close_pool() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """The open transaction's connection, or a pooled autocommit one."""
    conn = _current_conn.get()
    if conn is not None:
        yield conn
        return
    with _opened().connection() as conn:
        yield conn


@contextmanager
def transaction() -> Iterator[psycopg.Connection]:
    """One transaction for the block; nested calls become savepoints."""
    conn = _current_conn.get()
    if conn is not None:
        with conn.transaction():
            yield conn
        return
    with _opened().connection() as conn:
        token = _current_conn.set(conn)
        try:
            with conn.transaction():
                yield conn
        finally:
            _current_conn.reset(token)


def exec_(sql: str, params: Params = None) -> int:
    """Run a statement; return the affected row count."""
    with connection() as conn:
        try:
            return conn.execute(sql, params).rowcount
        except psycopg.Error as exc:
            raise translate(exc) from exc


def q1(sql: str, params: Params = None) -> Optional[dict]:
    with connection() as conn:
        try:
            return conn.execute(sql, params).fetchone()
        except psycopg.Error as exc:
            raise translate(exc) from exc


def q(sql: str, params: Params = None) -> list[dict]:
    with connection() as conn:
        try:
            return conn.execute(sql, params).fetchall()
        except psycopg.Error as exc:
            raise translate(exc) from exc


def ping(timeout: float = 1.0) -> bool:
    """SELECT 1 within `timeout` seconds; False on any failure."""
    try:
        with _opened().connection(timeout=timeout) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
