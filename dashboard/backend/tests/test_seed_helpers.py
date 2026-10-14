"""tests/helpers/seed.py makes linked rows with real uuids."""
import uuid

from tests.helpers.seed import make_domain, make_origin, make_user


def test_seed_chain_uses_real_uuids(db):
    owner = make_user(role="admin")
    origin = make_origin(owner, db=db)
    domain = make_domain(origin, db=db)
    for value in (owner["user_id"], origin["id"], domain["id"]):
        assert uuid.UUID(value)
    assert domain["origin_id"] == origin["id"]
    assert origin["admin_user_id"] == owner["user_id"]
    assert db.get_domain_by_name(domain["domain_name"])["id"] == domain["id"]
