"""Per-user cap on Gemini-backed features (re-audit 2026-10-17).

Copilot chat and summarize-range spend the operator's Gemini key on every
call and are open to any self-registered account. Like predict-and-suggest
(F-113), they are capped per user, not per IP (behind Caddy every caller
shares one remote address). One shared bucket covers both features.
"""
import os

from fastapi import HTTPException

AI_CALLS_PER_HOUR = int(os.getenv("AI_CALLS_PER_HOUR", "60"))
_limiter = None


def check_ai_quota(user_id: str) -> None:
    global _limiter
    if _limiter is None:
        from services.rate_limiter import RedisRateLimiter
        _limiter = RedisRateLimiter()
    # Fail closed: an unchecked quota is exactly the unlimited spend this caps.
    allowed, _, retry_after = _limiter.is_allowed(
        f"ai-quota:{user_id}", AI_CALLS_PER_HOUR, 3600, fail_open=False
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"AI request limit reached ({AI_CALLS_PER_HOUR}/hour). Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
