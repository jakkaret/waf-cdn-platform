import re
from fastapi import APIRouter, Request, Response, HTTPException, status
from services.rate_limiter import RedisRateLimiter
from services.rate_limit_service import RateLimitService

router = APIRouter(prefix="/api/limiter", tags=["Rate Limiting"])
rate_limiter = RedisRateLimiter()
rule_service = RateLimitService()

# Regex matching static web assets that should never be throttled
STATIC_EXT_REGEX = re.compile(
    r"\.(css|js|jsx|ts|tsx|jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|eot|otf|json|map|txt|xml|mp4|webm)$",
    re.IGNORECASE
)


def is_static_asset(path: str) -> bool:
    """Check if the URI targets a static asset or SPA bundle."""
    clean_path = path.split("?")[0].strip()
    if clean_path.startswith("/assets/") or clean_path.startswith("/static/"):
        return True
    if clean_path in ["/styles.css", "/main.js", "/polyfills.js", "/scripts.js", "/runtime.js", "/favicon.ico"]:
        return True
    return bool(STATIC_EXT_REGEX.search(clean_path))


@router.api_route("/check", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def check_rate_limit(request: Request, response: Response):
    # 1. Retrieve client IP and requested URI
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.headers.get("X-Real-IP")
        
    if not client_ip:
        client_ip = request.client.host if request.client else "127.0.0.1"

    original_uri = request.headers.get("X-Original-URI") or request.url.path or "/"
    clean_uri = original_uri.split("?")[0]
    http_method = request.method.upper()

    # 2. Whitelist static assets from rate limiting to prevent broken UI
    if is_static_asset(clean_uri):
        response.headers["X-RateLimit-Bypass"] = "static-asset"
        return {"status": "allowed", "type": "static_asset"}

    # 3. Dynamic rule evaluation from RateLimitService
    limit = 100
    window_seconds = 10

    try:
        rules = rule_service.list_rules()
        for rule in rules:
            if not rule.get("enabled", 1):
                continue
            r_method = rule.get("method", "ALL").upper()
            if r_method != "ALL" and r_method != http_method:
                continue

            r_pattern = rule.get("path_pattern", "*")
            # Simple wildcard pattern matching
            if r_pattern == "*" or r_pattern == clean_uri:
                limit = rule.get("limit_count", limit)
                window_seconds = rule.get("window_seconds", window_seconds)
                break
            elif r_pattern.endswith("*") and clean_uri.startswith(r_pattern[:-1]):
                limit = rule.get("limit_count", limit)
                window_seconds = rule.get("window_seconds", window_seconds)
                break
    except Exception as e:
        pass

    # 4. Check Redis Sliding Window Rate Limit
    is_allowed, current_count, retry_after = rate_limiter.is_allowed(
        ip=client_ip,
        limit=limit,
        window_seconds=window_seconds
    )
    
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )
        
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count))
    return {"status": "allowed", "current_requests": current_count}
