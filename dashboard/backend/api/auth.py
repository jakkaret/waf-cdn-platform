from fastapi import APIRouter, HTTPException, Depends, Response, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
from services.auth_service import AuthService
from services.rbac import get_current_user, require_admin

# สร้าง router สำหรับ auth โดยกำหนด prefix เป็น /api/auth
router = APIRouter(prefix="/api/auth", tags=["auth"])
auth_service = AuthService()


# ------------------------------------------------------------------
# Schemas - กำหนดรูปแบบข้อมูลที่รับเข้ามาแต่ละ endpoint
# ------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr      # ตรวจสอบรูปแบบ email อัตโนมัติ
    username: str        # ชื่อที่แสดงในระบบ
    password: str        # รหัสผ่าน
    role: Optional[str] = "viewer"  # role เริ่มต้นเป็น viewer


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TelegramLoginRequest(BaseModel):
    id: int                          # Telegram user ID
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    username: Optional[str] = ""
    photo_url: Optional[str] = ""
    auth_date: int                   # เวลาที่ login (Unix timestamp)
    hash: str                        # ลายเซ็นจาก Telegram สำหรับตรวจสอบความถูกต้อง


class UpdateRoleRequest(BaseModel):
    role: str  # admin หรือ viewer


# ------------------------------------------------------------------
# Local register / login
# ------------------------------------------------------------------

@router.post("/register")
async def register(req: RegisterRequest, response: Response):
    # ตรวจสอบว่ามี user อยู่ในระบบแล้วหรือยัง
    existing_users = auth_service.list_users()
    role = req.role

    if len(existing_users) == 0:
        # ถ้ายังไม่มี user เลย คนแรกจะได้เป็น admin อัตโนมัติ
        role = "admin"
    elif role == "admin":
        # ป้องกันไม่ให้สมัครเป็น admin เองได้ ต้องให้ admin คนอื่น promote ให้
        role = "viewer"

    try:
        user = auth_service.register_local(
            email=req.email,
            username=req.username,
            password=req.password,
            role=role,
        )
    except ValueError as e:
        # กรณี email ซ้ำหรือข้อมูลไม่ถูกต้อง
        raise HTTPException(status_code=400, detail=str(e))

    # สร้าง JWT token สำหรับ session
    token = auth_service.create_access_token({
        "sub": user["user_id"],  # subject คือ user_id
        "role": user["role"],
        "email": user["email"],
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),  # ส่งข้อมูล user กลับไป (ไม่รวม password_hash)
    }


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    try:
        # ตรวจสอบ email และ password กับ DynamoDB
        user = auth_service.login_local(req.email, req.password)
    except ValueError as e:
        # กรณี account นี้ใช้ Google หรือ Telegram login อยู่
        raise HTTPException(status_code=400, detail=str(e))

    if not user:
        # email หรือ password ผิด
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # สร้าง JWT token
    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


@router.post("/logout")
async def logout(response: Response):
    # ลบ cookie access_token ออก
    response.delete_cookie("access_token")
    return {"message": "Logged out"}


# ------------------------------------------------------------------
# Google OAuth
# ------------------------------------------------------------------

@router.get("/google")
async def google_login():
    # สร้าง URL สำหรับ redirect ไปหน้า login ของ Google
    url = auth_service.get_google_auth_url()
    return RedirectResponse(url)


@router.get("/google/callback")
async def google_callback(code: str):
    # Google redirect กลับมาพร้อม code สำหรับแลก token
    google_user = auth_service.exchange_google_code(code)
    if not google_user:
        raise HTTPException(status_code=400, detail="Google authentication failed")

    # ถ้ามี account อยู่แล้วให้ login เลย ถ้าไม่มีให้สร้างใหม่
    user = auth_service.login_or_register_google(google_user)

    # สร้าง JWT token
    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user["email"],
    })

    # ส่ง token ผ่าน URL แทน cookie เพราะ JavaScript อ่าน httponly cookie ไม่ได้
    # auth.js จะดึง token จาก URL แล้วเก็บลง localStorage
    return RedirectResponse(url=f"/?token={token}", status_code=302)


# ------------------------------------------------------------------
# Telegram Login Widget
# ------------------------------------------------------------------

@router.post("/telegram")
async def telegram_login(req: TelegramLoginRequest, response: Response):
    data = req.dict()

    # ตรวจสอบลายเซ็น HMAC จาก Telegram ว่าข้อมูลถูกต้องและไม่ถูกปลอมแปลง
    if not auth_service.verify_telegram_login(data):
        raise HTTPException(status_code=401, detail="Telegram verification failed")

    # ถ้ามี account อยู่แล้วให้ login เลย ถ้าไม่มีให้สร้างใหม่
    user = auth_service.login_or_register_telegram(req.dict())

    token = auth_service.create_access_token({
        "sub": user["user_id"],
        "role": user["role"],
        "email": user.get("email", ""),
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _safe_user(user),
    }


# ------------------------------------------------------------------
# Current user info
# ------------------------------------------------------------------

@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    # ดึงข้อมูล user ของตัวเองจาก JWT token ที่ส่งมา
    return _safe_user(current_user)


# ------------------------------------------------------------------
# User management (admin only)
# ------------------------------------------------------------------

@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)):
    # ดูรายชื่อ user ทั้งหมด เฉพาะ admin เท่านั้น
    users = auth_service.list_users()
    return {"users": [_safe_user(u) for u in users]}


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    req: UpdateRoleRequest,
    admin: dict = Depends(require_admin),  # ต้องเป็น admin เท่านั้น
):
    # เปลี่ยน role ของ user เช่น viewer -> admin
    try:
        auth_service.update_user_role(user_id, req.role)
        return {"message": "Role updated"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_user(user: dict) -> dict:
    # กรองข้อมูลที่ส่งกลับไปให้ client
    # ไม่รวม password_hash เพื่อความปลอดภัย
    return {
        "user_id": user.get("user_id"),
        "email": user.get("email"),
        "username": user.get("username"),
        "role": user.get("role"),
        "auth_provider": user.get("auth_provider"),  # local, google, telegram
        "avatar_url": user.get("avatar_url", ""),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
    }