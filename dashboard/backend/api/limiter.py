from fastapi import APIRouter, Request, Response, HTTPException, status
from services.rate_limiter import RedisRateLimiter

router = APIRouter(prefix="/api/limiter", tags=["Rate Limiting"])
rate_limiter = RedisRateLimiter()

# Default limit: 10 requests per 10 seconds
DEFAULT_LIMIT = 10
DEFAULT_WINDOW = 10

@router.api_route("/check", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def check_rate_limit(request: Request, response: Response):
    # Retrieve client IP
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.headers.get("X-Real-IP")
        
    if not client_ip:
        client_ip = request.client.host if request.client else "127.0.0.1"
        
    is_allowed, current_count, retry_after = rate_limiter.is_allowed(
        ip=client_ip,
        limit=DEFAULT_LIMIT,
        window_seconds=DEFAULT_WINDOW
    )
    
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )
        
    response.headers["X-RateLimit-Limit"] = str(DEFAULT_LIMIT)
    response.headers["X-RateLimit-Remaining"] = str(DEFAULT_LIMIT - current_count)
    return {"status": "allowed", "current_requests": current_count}
