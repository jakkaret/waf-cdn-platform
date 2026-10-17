import os
import time
import hmac
import hashlib
import base64
import secrets
from urllib.parse import urlencode, urlparse
import logging
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv, find_dotenv
import jwt  # PyJWT (replaced python-jose 2026-09-30 to drop the ecdsa CVE dep)

logger = logging.getLogger(__name__)

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

load_dotenv(find_dotenv())

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if not SECRET_KEY:
    # A built-in fallback secret is public (this repo is public), so anyone
    # could sign an admin token. Refuse to start instead.
    raise RuntimeError("JWT_SECRET_KEY is not set")
if "$(" in SECRET_KEY or "`" in SECRET_KEY:
    # .env files are not run through a shell: "JWT_SECRET_KEY=$(openssl rand
    # -hex 32)" stores that literal text, which is public (found on Main
    # 2026-10-15). Refuse it like an empty key.
    raise RuntimeError("JWT_SECRET_KEY is an unexpanded shell command, not a secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES") or "60")  # empty value = default

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://waf-it-kku.online/api/auth/google/callback")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# Google sign-in never grants admin (re-audit 2026-10-17): the old
# ADMIN_EMAIL_DOMAIN rule promoted every verified address on a domain, so a
# shared domain (e.g. a university) would make all its users platform admins.
# Admins come only from scripts/seed_admin.py or an existing admin.

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
)


def _invalidate_alert_recipients() -> None:
    """Telegram recipients are cached for 60 s; drop the cache when a role or
    an account changes so alerts follow the new permissions at once."""
    try:
        from services.telegram_listener import invalidate_user_cache
        invalidate_user_cache()
    except Exception as exc:  # never block a role change on the alert cache
        logger.warning("could not invalidate the alert recipient cache: %s", exc)


class GoogleLoginRejected(Exception):
    """Google sign-in refused; str(exc) is a short code for the login page."""


class AuthService:
    """Accounts in PostgreSQL (waf.users + waf.user_identities) through
    services.pg_store.PgUserRepository. Returned user dicts keep the shape
    callers rely on (see PgUserRepository). __init__ does no I/O: scripts and
    tests build this at module level."""

    backend = "postgres"

    def __init__(self):
        from services.pg_store import PgUserRepository
        self._pg = PgUserRepository()

    def hash_password(self, password: str) -> str:
        return ph.hash(password)

    def verify_password(self, plain: str, hashed: str) -> bool:
        try:
            return ph.verify(hashed, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        # A dashboard session carries the user's token_version (H28/H31);
        # typed tokens (tunnel tokens) are revoked by other means.
        if to_encode.get("sub") and "type" not in to_encode and "tv" not in to_encode:
            user = self.get_user_by_id(str(to_encode["sub"]))
            to_encode["tv"] = int((user or {}).get("token_version") or 0)
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def decode_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.PyJWTError:
            return None

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        try:
            return self._pg.get_by_id(user_id)
        except Exception as e:
            logger.error("get_user_by_id error: %s", e)
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        try:
            return self._pg.get_by_email(email)
        except Exception as e:
            logger.error("get_user_by_email error: %s", e)
            return None

    def get_user_by_provider(self, provider: str, provider_id: str) -> Optional[Dict]:
        try:
            return self._pg.get_by_provider(provider, provider_id)
        except Exception as e:
            logger.error("get_user_by_provider error: %s", e)
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
        """Insert a user (and its Google/Telegram identity, same transaction).
        A duplicate email or identity raises a ValueError."""
        if auth_provider == "local" and not password:
            raise ValueError("Password is required")
        return self._pg.create(
            email=email, username=username,
            password_hash=self.hash_password(password) if password else None,
            role=role, auth_provider=auth_provider, provider_id=provider_id,
            avatar_url=avatar_url,
        )

    def update_last_login(self, user_id: str):
        try:
            self._pg.touch_login(user_id)
        except Exception as e:
            logger.error("update_last_login error: %s", e)

    def list_users(self):
        try:
            return self._pg.list()
        except Exception as e:
            logger.error("list_users error: %s", e)
            return []

    def count_users(self) -> int:
        return self._pg.count()

    def list_telegram_recipients(self):
        """Users who connected a Telegram chat for alert delivery."""
        try:
            return self._pg.list_telegram_recipients()
        except Exception as e:
            logger.error("list_telegram_recipients error: %s", e)
            return []

    def set_telegram_chat_id(self, user_id: str, chat_id: Optional[str]) -> None:
        """Connect ('123') or disconnect (None/'') the user's alert chat."""
        self._pg.set_field(user_id, "telegram_chat_id", str(chat_id) if chat_id else None)

    def update_user_role(self, user_id: str, role: str):
        if role not in {"admin", "viewer"}:
            raise ValueError("Invalid role")
        if not self._pg.set_field(user_id, "role", role):
            raise ValueError("User not found")
        # Sessions issued under the old role must not keep it, and a demoted
        # admin must stop receiving every tenant's alerts now (H25/H34).
        self.revoke_sessions(user_id)
        _invalidate_alert_recipients()

    def revoke_sessions(self, user_id: str) -> None:
        """Every device: bumps token_version (voids all tokens) and marks the
        account's session rows revoked."""
        self._pg.bump_token_version(user_id)
        self._pg.revoke_all_sessions(user_id)

    def start_session(self, user: Dict, user_agent: str = "", ip: str = "") -> str:
        """Sign-in on one device: a session row plus a JWT naming it (sid)."""
        sid = self._pg.create_session(user["user_id"], ACCESS_TOKEN_EXPIRE_MINUTES * 60, user_agent, ip)
        return self.create_access_token({
            "sub": user["user_id"],
            "role": user["role"],
            "email": user.get("email", ""),
            "sid": sid,
        })

    def end_session(self, payload: Dict) -> None:
        """Logout on this device only. A token from before per-device
        sessions (no sid) falls back to signing out everywhere."""
        if payload.get("sid"):
            self._pg.revoke_session(payload["sid"], payload.get("sub", ""))
        elif payload.get("sub"):
            self._pg.bump_token_version(payload["sub"])

    def delete_user(self, user_id: str) -> int:
        """Delete the account; origins it still owns are archived in the same
        transaction. Returns how many were archived."""
        archived = self._pg.delete(user_id)
        _invalidate_alert_recipients()
        return archived

    def set_threat_intel_opt_in(self, user_id: str, enabled: bool) -> None:
        """services/threat_intel.py reads this field fresh (never cached) on
        every write and read, so opting out here takes effect on the very
        next attack -- see that module's docstring for why that direction
        matters more than opt-in lag would."""
        self._pg.set_field(user_id, "share_threat_intel", bool(enabled))

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

    # --- Google OAuth (N21: state + PKCE + nonce; N10: no linking by email) ---
    # The per-login state, PKCE verifier and nonce travel in a short-lived
    # HttpOnly cookie, signed with a key derived from (not equal to) the session
    # key so it can never be mistaken for a session token.
    _OAUTH_KEY_SUFFIX = "|google-oauth-flow"

    def start_google_flow(self, link: bool = False) -> Tuple[str, str]:
        """Returns (auth_url, signed_flow_cookie)."""
        # The authorization code must never travel over plain http (H30).
        parsed = urlparse(GOOGLE_REDIRECT_URI)
        if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
            raise RuntimeError("GOOGLE_REDIRECT_URI must be an https URL")
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(24)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        flow = jwt.encode(
            {"state": state, "cv": verifier, "nonce": nonce, "link": bool(link),
             "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
            SECRET_KEY + self._OAUTH_KEY_SUFFIX, algorithm=ALGORITHM)
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}", flow

    def read_google_flow(self, flow_cookie: Optional[str], state: Optional[str]) -> Optional[Dict]:
        """The flow started in this browser, if state matches; else None."""
        if not flow_cookie or not state:
            return None
        try:
            flow = jwt.decode(flow_cookie, SECRET_KEY + self._OAUTH_KEY_SUFFIX, algorithms=[ALGORITHM])
        except Exception:
            return None
        if not hmac.compare_digest(str(flow.get("state", "")), str(state)):
            return None
        return flow

    def exchange_google_code(self, code: str, code_verifier: str, nonce: str) -> Optional[Dict]:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
            timeout=10,
        )
        if token_resp.status_code != 200:
            logger.warning("Google token exchange failed: HTTP %s", token_resp.status_code)
            return None

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        # The id_token comes straight from Google's token endpoint over TLS, so
        # its claims can be read without re-verifying the signature (OIDC 3.1.3.7).
        try:
            claims = jwt.decode(tokens.get("id_token", ""), options={"verify_signature": False})
        except Exception:
            return None
        if not hmac.compare_digest(str(claims.get("nonce", "")), str(nonce)):
            logger.warning("Google id_token nonce mismatch")
            return None

        info_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_resp.status_code != 200:
            return None

        return info_resp.json()

    def login_or_register_google(self, google_user: Dict, link_to: Optional[Dict] = None) -> Dict:
        """N10: Google signs in only to an account it is linked to. An email
        match alone never grants access to an existing account: the owner must
        sign in with the password first and link Google (link_to)."""
        provider_id = google_user.get("sub")
        email = google_user.get("email", "")
        name = google_user.get("name", email.split("@")[0])
        avatar = google_user.get("picture", "")
        if not provider_id or google_user.get("email_verified") is not True:
            raise GoogleLoginRejected("google_email_unverified")

        user = self.get_user_by_provider("google", provider_id)
        if link_to is not None:
            if user and user["user_id"] != link_to["user_id"]:
                raise GoogleLoginRejected("google_linked_elsewhere")
            if not user:
                try:
                    self._pg.link_identity(link_to["user_id"], "google", provider_id)
                except ValueError:
                    raise GoogleLoginRejected("google_link_conflict")
            user = self.get_user_by_id(link_to["user_id"])
        elif not user and self.get_user_by_email(email):
            raise GoogleLoginRejected("google_link_required")

        if user:
            self.update_last_login(user["user_id"])
            if not user.get("avatar_url") and avatar:
                self._pg.set_field(user["user_id"], "avatar_url", avatar)
                user["avatar_url"] = avatar
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
