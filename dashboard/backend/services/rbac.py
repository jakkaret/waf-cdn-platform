from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
from services.auth_service import AuthService

auth_service = AuthService()
bearer_scheme = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    # Try Authorization header first
    if credentials and credentials.credentials:
        return credentials.credentials
    # Fall back to cookie
    return request.cookies.get("access_token")


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = auth_service.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Tunnel tokens (type=tunnel_token, ~365 days) are bearer credentials for
    # the FRP gatekeeper only (api/tunnels.py decodes them directly). They must
    # never act as a dashboard session. (F-021)
    if payload.get("type") == "tunnel_token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = auth_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # "Sign out everywhere", role and password changes bump token_version;
    # tokens issued before that are void on every device.
    if int(payload.get("tv", 0)) != int(user.get("token_version") or 0):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Per-device session: logout on this device revokes only this one.
    # Tokens from before per-device sessions carry no sid and expire on
    # their own within the 60-minute token lifetime.
    sid = payload.get("sid")
    if sid and not auth_service._pg.session_active(sid, user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(roles: List[str]):
    def dependency(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {roles}. Your role: {current_user.get('role')}",
            )
        return current_user
    return dependency


# Until the owner proves the address with the emailed code (api/auth.py
# /verify-email), an account can sign in and look around but cannot do what
# reaches the edge or other people: add a site or domain, mint agent tokens,
# send or accept team invitations, or use the AI features. The 403 detail
# carries the blocked action so the UI can say why it matters.
def email_verified(user: dict) -> bool:
    return bool(user.get("email_verified"))


def require_verified_email(action: str):
    def dependency(current_user: dict = Depends(get_current_user)):
        if not email_verified(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "email_unverified", "action": action,
                        "message": "ยืนยันอีเมลก่อนใช้งานส่วนนี้"},
            )
        return current_user
    return dependency


# Shorthand dependencies
def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def require_viewer_or_above(current_user: dict = Depends(get_current_user)):
    allowed = {"viewer", "admin"}
    if current_user.get("role") not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return current_user

# Soft-deleted origins carry status "archived" (origin_service), and older rows
# may carry "deleted". Both mean gone as far as every route except restore.
ARCHIVED_ORIGIN_STATUSES = ("archived", "deleted")


def verify_origin_ownership(
    origin_id: str,
    current_user: dict = Depends(get_current_user),
    allow_archived: bool = False,
):
    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    origin = db.get_origin_by_id(origin_id)
    if not origin or (not allow_archived and origin.get("status") in ARCHIVED_ORIGIN_STATUSES):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Origin not found")
    
    if not is_origin_owner(origin, current_user.get("user_id")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Only the owner of this origin can do that.")

    return origin


# Origin roles (2026-10-17): Owner > Editor > Viewer.
#   Owner  = the origin's creator (admin_user_id). Everything, including
#            delete/restore, team management (invite/remove members), tunnel
#            credentials and granting support access. Never removable.
#   Editor = editor_user_ids. Day-to-day changes: settings, domains, shield,
#            per-origin WAF rules, postmortems, support tickets.
#   Viewer = viewer_user_ids, read-only.
# verify_origin_ownership = Owner only; verify_origin_edit_access = Owner or
# Editor (is_origin_admin); verify_origin_access = any member.
def is_origin_owner(origin: dict, user_id: Optional[str]) -> bool:
    return bool(origin) and bool(user_id) and origin.get("admin_user_id") == user_id


def is_origin_admin(origin: dict, user_id: Optional[str]) -> bool:
    """Owner or Editor: may make day-to-day changes to the origin."""
    if not origin or not user_id:
        return False
    return origin.get("admin_user_id") == user_id or user_id in (origin.get("editor_user_ids") or set())


verify_origin_admin = verify_origin_ownership


def verify_origin_access(
    origin_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Read-only counterpart to verify_origin_ownership: the owner, a
    viewer, or an editor (Team Workspace, 2026-09-22) may read this origin.
    Without editor_user_ids here, a user granted only editor access would
    pass verify_origin_edit_access on writes but 403 on every read of the
    same origin -- a state no role should be in (an editor who can't even
    open the page they were just given write access to)."""
    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    origin = db.get_origin_by_id(origin_id)
    if not origin or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Origin not found")

    user_id = current_user.get("user_id")
    viewer_ids = origin.get("viewer_user_ids") or set()
    editor_ids = origin.get("editor_user_ids") or set()
    if origin.get("admin_user_id") != user_id and user_id not in viewer_ids and user_id not in editor_ids:
        if not _support_grant_allows(origin_id, current_user, "read"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You do not have access to this origin.")

    return origin


def _support_grant_allows(origin_id: str, current_user: dict, kind: str) -> bool:
    """Platform support staff (role admin) may use an origin while its admin
    has an active support grant open for it (docs/tickets/support-access.md):
    any level for reads, "editor" for edits. Never used by
    verify_origin_ownership. Each use is logged; if the log cannot be written
    the access is refused."""
    if current_user.get("role") != "admin":
        return False
    from services import support_service
    grant = support_service.active_grant(origin_id)
    if not grant or (kind == "edit" and grant.get("level") != "editor"):
        return False
    try:
        support_service.log_use(grant["grant_id"], origin_id, current_user.get("user_id"), kind)
    except Exception:
        return False
    return True


def verify_origin_edit_access(
    origin_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Team Workspace (2026-09-22): the owner or an editor may perform
    routine, reversible operational changes (update origin label/ip/port,
    CAPTCHA/OTP shield config, domain create/verify/delete). Deliberately
    NOT for: delete/restore origin, viewer/editor management, or minting
    tunnel credentials -- those stay on verify_origin_ownership,
    owner-only, unchanged. A viewer (read-only) is refused here same as
    before this feature existed."""
    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    origin = db.get_origin_by_id(origin_id)
    if not origin or origin.get("status") in ARCHIVED_ORIGIN_STATUSES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Origin not found")

    user_id = current_user.get("user_id")
    if not is_origin_admin(origin, user_id) and not _support_grant_allows(origin_id, current_user, "edit"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You do not have edit access to this origin.")

    return origin
