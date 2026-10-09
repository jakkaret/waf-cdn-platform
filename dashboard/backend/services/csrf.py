"""Double-submit CSRF protection for cookie-authenticated requests.

The dashboard authenticates with an HttpOnly session cookie, which the browser
attaches automatically -- so a cross-site form/fetch could ride it (CSRF). On a
state-changing method we require a non-HttpOnly csrf_token cookie to equal an
X-CSRF-Token header: an attacker's page can neither read our cookie (same
origin) nor set that header cross-site. Requests authenticated by an
Authorization: Bearer header instead (API clients, internal relays, the frps
webhook) are not cookie-driven and are exempt. SameSite=lax is a second layer.
"""
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def _secure() -> bool:
    return os.getenv("SESSION_COOKIE_SECURE", "true").lower() != "false"


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.method not in SAFE_METHODS:
            has_bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
            if request.cookies.get("access_token") and not has_bearer:
                cookie_csrf = request.cookies.get("csrf_token")
                header_csrf = request.headers.get("x-csrf-token")
                if not cookie_csrf or not header_csrf or header_csrf != cookie_csrf:
                    return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
        response = await call_next(request)
        # Self-heal: a session from before this change has no csrf cookie yet;
        # issue one on a safe request so the SPA can start sending the header
        # without a re-login.
        if request.cookies.get("access_token") and not request.cookies.get("csrf_token"):
            response.set_cookie(
                "csrf_token", secrets.token_urlsafe(32), httponly=False, samesite="lax",
                secure=_secure(), max_age=3600, path="/",
            )
        return response
