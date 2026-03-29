from fastapi import APIRouter, HTTPException, Depends, Response, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
from services.auth_service import AuthService
from services.rbac import get_current_user, require_admin

router = APIRouter(prefix="/api/auth", tags=["auth"])
auth_service = AuthService()


# Schemas

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: Optional[str] = "viewer"


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

@router.post("/register")
async def register(req: RegisterRequest, response: Response):
    # Only admin can create admin accounts
    # For the very first user, allow admin registration
    existing_users = auth_service.list_users()
    
    role = req.role
    if len(existing_users) == 0:
        # First user becomes admin automatically
        role = "admin"
    elif role == "admin":
        # Only admins can create other admins - enforced at route level
        # For simplicity, first registration as admin requires existing admin approval
        role = "viewer"

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

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


@router.post("/login")
async def login(req: LoginRequest, response: Response):
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

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out"}


# Google OAuth

@router.get("/google")
async def google_login():
    url = auth_service.get_google_auth_url()
    return RedirectResponse(url)


@router.get("/google/callback")
async def google_callback(code: str, response: Response):
    google_user = auth_service.exchange_google_code(code)
    if not google_user:
        raise HTTPException(status_code=400, detail="Google authentication failed")

    user = auth_service.login_or_register_google(google_user)

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    #redirect ไป oauth-success.html พร้อม token
    resp = RedirectResponse(
        url=f"/oauth-success.html?token={token}",
        status_code=302
    )
    resp.set_cookie(key="access_token", value=token, httponly=True, samesite="lax", max_age=3600)
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

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )

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
    }
