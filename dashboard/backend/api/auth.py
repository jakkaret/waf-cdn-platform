import asyncio
import os
from fastapi import APIRouter, HTTPException, Depends, Response, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field
from typing import Literal, Optional
from services.auth_service import AuthService, GoogleLoginRejected
from services.rbac import bearer_scheme, get_current_user, require_admin
from fastapi.security import HTTPAuthorizationCredentials
from services.rate_limiter import limiter

router = APIRouter(prefix="/api/auth", tags=["auth"])
auth_service = AuthService()

import os as _os
import secrets as _secrets

CSRF_COOKIE_NAME = "csrf_token"
SESSION_MAX_AGE = 3600


def _cookie_secure() -> bool:
    # HTTPS in production (behind Caddy) -> Secure by default. Tests run over
    # http via TestClient and set SESSION_COOKIE_SECURE=false so the cookie is
    # still sent back.
    return _os.getenv("SESSION_COOKIE_SECURE", "true").lower() != "false"


def _set_session_cookies(response, token: str) -> None:
    """Session is an HttpOnly cookie (JS can't read it -> XSS can't steal it);
    a companion non-HttpOnly csrf_token cookie backs double-submit CSRF."""
    secure = _cookie_secure()
    response.set_cookie("access_token", token, httponly=True, samesite="lax",
                        secure=secure, max_age=SESSION_MAX_AGE, path="/")
    response.set_cookie(CSRF_COOKIE_NAME, _secrets.token_urlsafe(32), httponly=False,
                        samesite="lax", secure=secure, max_age=SESSION_MAX_AGE, path="/")


def _clear_session_cookies(response) -> None:
    for k in ("access_token", CSRF_COOKIE_NAME):
        response.delete_cookie(k, path="/", samesite="lax", secure=_cookie_secure())


# Schemas

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str = Field(min_length=1)
    role: Optional[Literal["admin", "viewer"]] = "admin"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TelegramLoginRequest(BaseModel):
    id: int
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    username: Optional[str] = ""
    photo_url: Optional[str] = ""
    auth_date: int
    hash: str


class UpdateRoleRequest(BaseModel):
    role: str


# Local register / login

def _first_user_admin_enabled() -> bool:
    return _os.getenv("WAF_FIRST_USER_ADMIN", "false").strip().lower() == "true"


@router.post("/register")
@limiter.limit("10/minute")
async def register(request: Request, req: RegisterRequest, response: Response):
    # Self-registration never grants admin. The first admin is seeded by an
    # operator (scripts/seed_admin.py): on the public site, "the first user
    # to register becomes admin" handed the platform to whoever signed up
    # first after the database was reset. WAF_FIRST_USER_ADMIN=true restores
    # the old bootstrap rule (the test suite uses it).
    role = "viewer"
    if _first_user_admin_enabled() and auth_service.count_users() == 0:
        role = "admin"

    try:
        user = auth_service.register_local(
            email=req.email,
            username=req.username,
            password=req.password,
            role=role,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    _set_session_cookies(response, token)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, req: LoginRequest, response: Response):
    try:
        user = auth_service.login_local(req.email, req.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    _set_session_cookies(response, token)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


@router.post("/logout")
async def logout(request: Request, response: Response,
                 credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)):
    # Revoke the session server-side too (H28/H31): a copied token must not
    # outlive the logout. Logging out without a valid session still clears cookies.
    try:
        user = get_current_user(request, credentials)  # cookie or Bearer header
        auth_service.revoke_sessions(user["user_id"])
    except HTTPException:
        pass
    _clear_session_cookies(response)
    return {"message": "Logged out"}


# Google OAuth

GOOGLE_FLOW_COOKIE = "g_oauth_flow"
GOOGLE_FLOW_PATH = "/api/auth/google"


def _google_error(code: str) -> RedirectResponse:
    resp = RedirectResponse(url=f"/login?error={code}", status_code=302)
    resp.delete_cookie(GOOGLE_FLOW_COOKIE, path=GOOGLE_FLOW_PATH, samesite="lax", secure=_cookie_secure())
    return resp


@router.get("/google")
async def google_login(request: Request, link: bool = False):
    """Start Google sign-in. link=true attaches Google to the account that is
    signed in right now (the only way to use Google on an existing account)."""
    if link:
        get_current_user(request, None)  # 401 unless signed in
    url, flow = auth_service.start_google_flow(link=link)
    resp = RedirectResponse(url)
    resp.set_cookie(GOOGLE_FLOW_COOKIE, flow, httponly=True, samesite="lax",
                    secure=_cookie_secure(), max_age=600, path=GOOGLE_FLOW_PATH)
    return resp


@router.get("/google/callback")
async def google_callback(request: Request, code: str = "", state: str = ""):
    # N21: the callback must finish a flow this browser started (state), with
    # the PKCE verifier and nonce from that flow.
    flow = auth_service.read_google_flow(request.cookies.get(GOOGLE_FLOW_COOKIE), state)
    if not flow or not code:
        return _google_error("google_state")
    google_user = auth_service.exchange_google_code(code, flow["cv"], flow["nonce"])
    if not google_user:
        return _google_error("google_failed")

    link_to = None
    if flow.get("link"):
        try:
            link_to = get_current_user(request, None)
        except HTTPException:
            return _google_error("google_link_session")
    try:
        user = auth_service.login_or_register_google(google_user, link_to=link_to)
    except GoogleLoginRejected as exc:
        return _google_error(str(exc))

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    # [S2 FIX] ห้ามแนบ JWT token ใน URL query param
    # เพราะถูกบันทึกใน browser history, server access logs, และ Referrer header
    # ใช้ HttpOnly cookie เป็น auth mechanism เพียงอย่างเดียว
    # Frontend จะเรียก GET /api/auth/me ผ่าน cookie เพื่อ hydrate session เอง
    resp = RedirectResponse(
        url="/settings?google=linked" if link_to else "/oauth-success",
        status_code=302
    )
    resp.delete_cookie(GOOGLE_FLOW_COOKIE, path=GOOGLE_FLOW_PATH, samesite="lax", secure=_cookie_secure())
    _set_session_cookies(resp, token)
    return resp


# Telegram Login Widget

@router.post("/telegram")
async def telegram_login(req: TelegramLoginRequest, response: Response):
    data = req.dict()
    
    if not auth_service.verify_telegram_login(data):
        raise HTTPException(status_code=401, detail="Telegram verification failed")

    user = auth_service.login_or_register_telegram(req.dict())

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user.get("email", ""),
    })

    _set_session_cookies(response, token)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


# Current user info

@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    return _safe_user(current_user)


# User management (admin only)

@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)):
    users = auth_service.list_users()
    return {"users": [_safe_user(u) for u in users]}


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    req: UpdateRoleRequest,
    admin: dict = Depends(require_admin),
):
    try:
        auth_service.update_user_role(user_id, req.role)
        return {"message": "Role updated"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: dict = Depends(require_admin),
):
    if user_id == admin.get("user_id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    # Origins the user still owns are archived with the deletion.
    archived = auth_service.delete_user(user_id) or 0
    if archived:
        from services.origin_service import _invalidate_origins_caches
        from services.tenant_service import invalidate_tenant_cache
        invalidate_tenant_cache()
        _invalidate_origins_caches()
        # P2.2: the archived origins' hosts lose their CAPTCHA/OTP keys.
        from services import shield_sync
        from services.dynamodb_service import DynamoDBService
        await asyncio.to_thread(shield_sync.reconcile_quietly, DynamoDBService())
    return {"message": "User deleted", "archived_origins": archived}


# Helpers

def _safe_user(user: dict) -> dict:
    return {
        "user_id": user.get("user_id"),
        "email": user.get("email"),
        "username": user.get("username"),
        "role": user.get("role"),
        "auth_provider": user.get("auth_provider"),
        "avatar_url": user.get("avatar_url", ""),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
        "share_threat_intel": bool(user.get("share_threat_intel", False)),
    }


# P3.8 (H04): the legacy POST /api/auth/tunnel/verify (an origin id used as
# the agent password) is gone; agents authenticate through
# /api/tunnel/verify-agent (per-origin credential) or the FRP hook.
