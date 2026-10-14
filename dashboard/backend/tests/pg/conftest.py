"""tests/pg: run against the throwaway database of tests/pg_harness.py and
start every test from empty tables (the top-level conftest only resets in
DATA_BACKEND=postgres mode)."""
import pytest

from tests import pg_harness


@pytest.fixture(autouse=True)
def _empty_pg_tables():
    if pg_harness.enabled():
        pg_harness.ensure_database()
        pg_harness.reset()
    yield
