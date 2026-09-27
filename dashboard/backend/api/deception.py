"""
FastAPI Router for WAF Dynamic Deception Layer (Honeypot).
Handles internal honeypot response generation, authentication, and administrative template inspection.
"""

import hmac
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from services.deception_service import (
    DeceptionLogEvent,
    DeceptionResponse,
    deception_service,
)
from services.rbac import require_admin

logger = logging.getLogger("waf.deception")

router = APIRouter(prefix="/api/deception", tags=["Deception"])

# Internal shared secret for proxy-to-backend authentication
INTERNAL_DECEPTION_HEADER = "X-Internal-Deception-Key"
INTERNAL_DECEPTION_KEY_ENV = "DECEPTION_INTERNAL_KEY"

def get_expected_key() -> str:
    """Dynamically resolves the expected key from environment."""
    return os.getenv(INTERNAL_DECEPTION_KEY_ENV, "")

def verify_internal_deception_key(request: Request) -> str:
    """
    Enforces shared secret verification for internal deception endpoints.
    Rejects direct unauthenticated or external access with HTTP 403 Forbidden.
    Safe against non-ASCII characters, surrogates, and timing attacks.
    """
    expected_key = get_expected_key()
    provided_key = request.headers.get(INTERNAL_DECEPTION_HEADER, "")

    is_valid = False
    if expected_key and provided_key:
        try:
            # Compare as UTF-8 encoded bytes to prevent TypeError on non-ASCII characters.
            # Using errors="ignore" protects against surrogate characters.
            is_valid = hmac.compare_digest(
                provided_key.encode("utf-8", errors="ignore"),
                expected_key.encode("utf-8"),
            )
        except Exception:
            is_valid = False

    if not is_valid:
        logger.warning(
            "Unauthorized access attempt to internal deception endpoint from IP: %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing internal deception key",
        )
    return provided_key


class DeceptionSimulateRequest(BaseModel):
    uri: str
    method: Optional[str] = "GET"
    body: Optional[str] = ""
    rule_id: Optional[str] = None
    template_id: Optional[str] = None


# ===========================================================================
# 1. Internal Deception Handler
# ===========================================================================

@router.api_route(
    "/respond",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    dependencies=[Depends(verify_internal_deception_key)],
    include_in_schema=False,
    summary="Generate contextual synthetic response for intercepted attacks",
)
async def respond_deception(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Internal honeypot responder triggered by Nginx error_page 418 redirect.
    Extracts original request metadata, dispatches to DeceptionService,
    and returns a synthetic response with strict anti-caching headers.
    """
    start_time = time.perf_counter()

    # 1. Extract original request attributes
    orig_uri = request.headers.get("X-Original-URI")
    if not orig_uri:
        q = request.url.query
        orig_uri = request.url.path + (f"?{q}" if q else "")

    orig_method = request.headers.get("X-Original-Method") or request.method or "GET"
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    client_ip = request.headers.get("X-Real-IP")
    if not client_ip:
        fwd = request.headers.get("X-Forwarded-For")
        client_ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "127.0.0.1")

    rule_id = request.headers.get("X-Matched-Rule-ID") or request.headers.get("X-ModSec-Rule-ID") or ""
    template_hint = request.headers.get("X-Deception-Template")

    # 2. Extract request body safely (bounded at 64 KB)
    raw_body = ""
    try:
        body_bytes = await request.body()
        if body_bytes:
            raw_body = body_bytes[:65536].decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug("Failed reading request body in deception handler: %s", e)

    import asyncio
    
    # 3. Generate synthetic response via DeceptionService with Fail-Safe Shield
    try:
        dec_response = await asyncio.wait_for(
            asyncio.to_thread(
                deception_service.generate_response,
                uri=orig_uri,
                method=orig_method,
                body=raw_body,
                client_ip=client_ip,
                request_id=req_id,
                rule_id=rule_id,
                template_hint=template_hint,
                headers=dict(request.headers),
            ),
            timeout=1.0
        )
    except asyncio.TimeoutError:
        logger.error("DeceptionService execution timed out (>1.0s). Enforcing fail-safe synthetic response.")
        dec_response = deception_service.get_fallback_response(request_id=req_id)
    except Exception as exc:
        logger.error(
            "DeceptionService execution error: %s. Enforcing fail-safe synthetic response.",
            exc,
            exc_info=True,
        )
        dec_response = deception_service.get_fallback_response(request_id=req_id)

    # 4. Enqueue non-blocking fail-safe audit logging
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    log_event = DeceptionLogEvent(
        request_id=req_id,
        timestamp=int(time.time()),
        rule_id=rule_id,
        attack_category=dec_response.category,
        template_id=dec_response.template_id,
        response_status=dec_response.status_code,
        execution_result="deceived",
        client_ip=client_ip,
        method=orig_method,
        url=orig_uri,
        user_agent=request.headers.get("User-Agent", ""),
        edge_node="edge-th",
        host=(request.headers.get("X-Original-Host") or "")[:255],
        latency_ms=latency_ms,
        body_bytes_sent=len(dec_response.body.encode("utf-8")),
        datetime=datetime.utcnow().isoformat() + "Z",
    )
    background_tasks.add_task(deception_service.log_deception_event, log_event)

    # 5. Return HTTP 200 synthetic response immediately with anti-cache headers
    headers = dict(dec_response.headers)
    headers["X-Request-ID"] = req_id

    return Response(
        content=dec_response.body,
        status_code=dec_response.status_code,
        media_type=dec_response.content_type,
        headers=headers,
    )


# ===========================================================================
# 2. Administrative Deception Inspection
# ===========================================================================

@router.get(
    "/templates",
    summary="List available synthetic deception templates",
    dependencies=[Depends(require_admin)],
)
async def list_deception_templates():
    """Returns catalog of registered deception templates for admin dashboard."""
    templates = deception_service.list_templates()
    return {"templates": templates}


@router.post(
    "/simulate",
    summary="Simulate attack classification and preview synthetic response",
    dependencies=[Depends(require_admin)],
)
async def simulate_deception(payload: DeceptionSimulateRequest):
    """
    Dry-run simulation endpoint allowing administrators to test classification
    and inspect generated synthetic payloads.
    """
    result = deception_service.simulate(
        uri=payload.uri,
        method=payload.method or "GET",
        body=payload.body or "",
        rule_id=payload.rule_id,
        template_id=payload.template_id,
    )
    return result
