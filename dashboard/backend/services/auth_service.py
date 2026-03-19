import os
import time
import uuid
import hmac
import hashlib
from typing import Optional, Dict
from datetime import datetime, timedelta

import boto3
import requests
from dotenv import load_dotenv
from jose import jwt, JWTError
from boto3.dynamodb.conditions import Attr
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/google/callback")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
)


class AuthService:
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-southeast-1")
        self.dynamodb = boto3.resource(
            "dynamodb",
            region_name=self.region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
        self.users_table = self.dynamodb.Table("waf_users")

    def hash_password(self, password: str) -> str:
        return ph.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        try:
            return ph.verify(hashed, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def decode_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        try:
            resp = self.users_table.get_item(Key={"user_id": user_id})
            return resp.get("Item")
        except Exception as e:
            print("get_user_by_id error:", e)
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        try:
            resp = self.users_table.scan(
                FilterExpression=Attr("email").eq(email)
            )
            items = resp.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            print("get_user_by_email error:", e)
            return None

    def get_user_by_provider(self, provider: str, provider_id: str) -> Optional[Dict]:
        try:
            resp = self.users_table.scan(
                FilterExpression=Attr("auth_provider").eq(provider) & Attr("provider_id").eq(provider_id)
            )
            items = resp.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            print("get_user_by_provider error:", e)
            return None

    def create_user(
        self,
        email: str,
        username: str,
        password: Optional[str] = None,
        role: str = "viewer",
        auth_provider: str = "local",
        provider_id: Optional[str] = None,
        avatar_url: Optional[str] = None,
    ) -> Dict:
        user_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        item = {
            "user_id": user_id,
            "email": email,
            "username": username,
            "role": role,
            "auth_provider": auth_provider,
            "provider_id": provider_id or "",
            "avatar_url": avatar_url or "",
            "created_at": now,
            "last_login": now,
        }

        if password:
            item["password_hash"] = self.hash_password(password)
        else:
            item["password_hash"] = ""

        self.users_table.put_item(Item=item)
        return item

    def update_last_login(self, user_id: str):
        try:
            self.users_table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET last_login = :t",
                ExpressionAttributeValues={":t": datetime.utcnow().isoformat() + "Z"},
            )
        except Exception as e:
            print("update_last_login error:", e)

    def list_users(self):
        try:
            resp = self.users_table.scan()
            return resp.get("Items", [])
        except Exception as e:
            print("list_users error:", e)
            return []

    def update_user_role(self, user_id: str, role: str):
        allowed = {"admin", "viewer"}
        if role not in allowed:
            raise ValueError("Invalid role")
        self.users_table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET #r = :r",
            ExpressionAttributeNames={"#r": "role"},
            ExpressionAttributeValues={":r": role},
        )

    def register_local(self, email: str, username: str, password: str, role: str = "viewer") -> Dict:
        existing = self.get_user_by_email(email)
        if existing:
            raise ValueError("Email already registered")
        return self.create_user(email=email, username=username, password=password, role=role)

    def login_local(self, email: str, password: str) -> Optional[Dict]:
        user = self.get_user_by_email(email)
        if not user:
            return None
        if user.get("auth_provider", "local") != "local":
            raise ValueError("This account uses " + user["auth_provider"] + " login")
        if not self.verify_password(password, user.get("password_hash", "")):
            return None
        self.update_last_login(user["user_id"])
        return user

    def get_google_auth_url(self) -> str:
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://accounts.google.com/o/oauth2/v2/auth?{query}"

    def exchange_google_code(self, code: str) -> Optional[Dict]:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
        if token_resp.status_code != 200:
            print("Google token exchange failed:", token_resp.text)
            return None

        tokens = token_resp.json()
        access_token = tokens.get("access_token")

        info_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_resp.status_code != 200:
            return None

        return info_resp.json()

    def login_or_register_google(self, google_user: Dict) -> Dict:
        provider_id = google_user.get("sub")
        email = google_user.get("email", "")
        name = google_user.get("name", email.split("@")[0])
        avatar = google_user.get("picture", "")

        user = self.get_user_by_provider("google", provider_id)
        if not user:
            user = self.get_user_by_email(email)

        if user:
            self.update_last_login(user["user_id"])
            if not user.get("avatar_url") and avatar:
                self.users_table.update_item(
                    Key={"user_id": user["user_id"]},
                    UpdateExpression="SET avatar_url = :a",
                    ExpressionAttributeValues={":a": avatar},
                )
            return user

        return self.create_user(
            email=email,
            username=name,
            role="viewer",
            auth_provider="google",
            provider_id=provider_id,
            avatar_url=avatar,
        )

    def verify_telegram_login(self, data: Dict) -> bool:
        if not TELEGRAM_BOT_TOKEN:
            return False

        check_hash = data.pop("hash", None)
        if not check_hash:
            return False

        data_check_string = "\n".join(
            f"{k}={v}" for k, v in sorted(data.items())
        )

        secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
        computed = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

        auth_date = int(data.get("auth_date", 0))
        if time.time() - auth_date > 86400:
            return False

        return hmac.compare_digest(computed, check_hash)

    def login_or_register_telegram(self, tg_data: Dict) -> Dict:
        provider_id = str(tg_data.get("id"))
        first = tg_data.get("first_name", "")
        last = tg_data.get("last_name", "")
        username = tg_data.get("username", first)
        display_name = f"{first} {last}".strip() or username
        avatar = tg_data.get("photo_url", "")

        user = self.get_user_by_provider("telegram", provider_id)
        if user:
            self.update_last_login(user["user_id"])
            return user

        return self.create_user(
            email=f"tg_{provider_id}@telegram.local",
            username=display_name,
            role="viewer",
            auth_provider="telegram",
            provider_id=provider_id,
            avatar_url=avatar,
        )