"""
Scenario: 2026-09-22 (Team Workspace, overnight session) -- advisor review
before writing any endpoint code: "write the test that an editor gets 403
on delete before you write the grant endpoint" -- verify_origin_ownership
passing for an owner proves nothing about whether an editor is correctly
refused; that refusal is the test that actually catches a dependency wired
too broadly.

Covers the full decision matrix (services/rbac.py):
- verify_origin_access (read): owner, viewer, AND editor all pass.
- verify_origin_edit_access (routine, reversible changes): owner and
  editor pass, viewer is refused.
- verify_origin_ownership (destructive/management -- delete, restore,
  viewer/editor grant/revoke): owner only. An editor here must be refused
  exactly like a viewer always has been -- this endpoint's behavior is
  UNCHANGED by this feature, and that is the point being tested.
"""
import pytest
from fastapi import HTTPException

import services.rbac as rbac_module


def _origin(admin="user-owner", viewers=None, editors=None, status_="active"):
    return {
        "id": "origin-1",
        "admin_user_id": admin,
        "viewer_user_ids": set(viewers or []),
        "editor_user_ids": set(editors or []),
        "status": status_,
    }


@pytest.fixture()
def fake_get_origin(monkeypatch):
    """verify_origin_access/verify_origin_edit_access/verify_origin_ownership
    each do a local `from services.dynamodb_service import DynamoDBService;
    db = DynamoDBService()` -- patched by conftest's autouse fixture to the
    fake class already. Here we go one level more direct and monkeypatch
    get_origin_by_id itself so each test controls exactly what origin comes
    back, independent of what's actually in the fake store."""
    def _patch(origin: dict):
        monkeypatch.setattr(
            "services.dynamodb_service.DynamoDBService.get_origin_by_id",
            lambda self, origin_id: origin,
        )
    return _patch


# --------------------------------------------------------- verify_origin_access (read)

def test_owner_can_read(fake_get_origin):
    fake_get_origin(_origin(admin="u1"))
    result = rbac_module.verify_origin_access("origin-1", current_user={"user_id": "u1"})
    assert result["id"] == "origin-1"


def test_viewer_can_read(fake_get_origin):
    fake_get_origin(_origin(admin="u1", viewers=["u2"]))
    result = rbac_module.verify_origin_access("origin-1", current_user={"user_id": "u2"})
    assert result["id"] == "origin-1"


def test_editor_can_read(fake_get_origin):
    fake_get_origin(_origin(admin="u1", editors=["u3"]))
    result = rbac_module.verify_origin_access("origin-1", current_user={"user_id": "u3"})
    assert result["id"] == "origin-1"


def test_a_stranger_cannot_read(fake_get_origin):
    fake_get_origin(_origin(admin="u1"))
    with pytest.raises(HTTPException) as exc:
        rbac_module.verify_origin_access("origin-1", current_user={"user_id": "u-stranger"})
    assert exc.value.status_code == 403


# ------------------------------------------------- verify_origin_edit_access (write, safe)

def test_owner_has_edit_access(fake_get_origin):
    fake_get_origin(_origin(admin="u1"))
    result = rbac_module.verify_origin_edit_access("origin-1", current_user={"user_id": "u1"})
    assert result["id"] == "origin-1"


def test_editor_has_edit_access(fake_get_origin):
    fake_get_origin(_origin(admin="u1", editors=["u3"]))
    result = rbac_module.verify_origin_edit_access("origin-1", current_user={"user_id": "u3"})
    assert result["id"] == "origin-1"


def test_a_viewer_does_not_have_edit_access(fake_get_origin):
    """The one that matters: read access must never imply write access."""
    fake_get_origin(_origin(admin="u1", viewers=["u2"]))
    with pytest.raises(HTTPException) as exc:
        rbac_module.verify_origin_edit_access("origin-1", current_user={"user_id": "u2"})
    assert exc.value.status_code == 403


def test_a_stranger_does_not_have_edit_access(fake_get_origin):
    fake_get_origin(_origin(admin="u1"))
    with pytest.raises(HTTPException) as exc:
        rbac_module.verify_origin_edit_access("origin-1", current_user={"user_id": "u-stranger"})
    assert exc.value.status_code == 403


# --------------------------------------------- verify_origin_ownership (destructive/management)

def test_owner_passes_ownership_check(fake_get_origin):
    fake_get_origin(_origin(admin="u1"))
    result = rbac_module.verify_origin_ownership("origin-1", current_user={"user_id": "u1"})
    assert result["id"] == "origin-1"


def test_an_editor_is_refused_the_ownership_only_check(fake_get_origin):
    """The test advisor asked for explicitly: an editor must be refused on
    delete/restore/viewer-management/editor-management -- Team Workspace
    granting write access to *some* endpoints must never silently widen
    the owner-only gate on the destructive ones. This is the test that
    fails loudly if verify_origin_ownership were ever swapped out for
    verify_origin_edit_access on one of those endpoints by mistake."""
    fake_get_origin(_origin(admin="u1", editors=["u3"]))
    with pytest.raises(HTTPException) as exc:
        rbac_module.verify_origin_ownership("origin-1", current_user={"user_id": "u3"})
    assert exc.value.status_code == 403


def test_a_viewer_is_refused_the_ownership_only_check(fake_get_origin):
    fake_get_origin(_origin(admin="u1", viewers=["u2"]))
    with pytest.raises(HTTPException) as exc:
        rbac_module.verify_origin_ownership("origin-1", current_user={"user_id": "u2"})
    assert exc.value.status_code == 403
