"""In DATA_BACKEND=postgres mode the suite must really run on PgStore and a
real database -- never silently on the in-memory fake alone."""
import os

import pytest

from tests import pg_harness

pytestmark = pytest.mark.skipif(
    os.environ.get("DATA_BACKEND", "").strip().lower() != "postgres",
    reason="DATA_BACKEND is not postgres")


def test_store_class_is_pgstore_in_pg_mode():
    import services.dynamodb_service as dynamodb_service_module
    from services.pg_store import PgStore
    assert issubclass(dynamodb_service_module.DynamoDBService, PgStore)
    store = dynamodb_service_module.DynamoDBService()
    assert isinstance(store, PgStore)
    assert store.ping() is True


def test_tables_are_emptied_between_tests_part_1():
    from db import pool
    pool.exec_("INSERT INTO users (email, username, password_hash) "
               "VALUES ('leak-check@example.com', 'leak', '$argon2id$x')")
    assert pg_harness.count("users", "email = 'leak-check@example.com'") == 1


def test_tables_are_emptied_between_tests_part_2():
    assert pg_harness.count("users") == 0
    # the default rate-limit rules are back after every reset
    assert pg_harness.count("rate_limit_rules") == 3
