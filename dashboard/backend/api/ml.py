import ipaddress
import logging
import httpx
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from services.rbac import require_viewer_or_above
from services.gemini_service import gemini_service
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["ML Analyst"])

ML_SERVICE_URL = "http://127.0.0.1:5000"
INTERNAL_RELAY_HEADER = "X-Internal-ML-Relay"
INTERNAL_RELAY_VALUE = "nginx-shadow-v1"
INTERNAL_RELAY_NETWORK = ipaddress.ip_network("172.16.0.0/12")

class PredictRequest(BaseModel):
    url: str
    method: str = "GET"
    body: str = ""


async def _attach_explanation(req: PredictRequest, result: dict) -> dict:
    """Add a Thai explanation of the model's per-feature attribution (T9's
    `attribution`, T10 ruling R2) to a /predict result dict, shared by both
    endpoints below so the Gemini-calling logic exists in exactly one place.

    `attribution` may legitimately be absent from `result` (older ML service,
    or T9 could not compute it) -- GeminiService.explain_attribution handles
    that as a normal case and returns a static fallback with no network call.
    A slow/dead Gemini cannot block a prediction: explain_attribution itself
    is designed to never raise and bounds its own HTTP call to an 8s timeout.

    Binding project constraint: detection availability outranks explanation
    availability, always. explain_attribution() is defense-in-depth against
    ever raising, but this call site does not *trust* that -- if it raises
    for any reason at all, the prediction must still return, just without an
    "explanation" key, rather than turning a successful detection into a
    500.
    """
    attribution = result.get("attribution")
    request_context = {"url": req.url, "method": req.method}
    try:
        result["explanation"] = await gemini_service.explain_attribution(request_context, attribution)
    except Exception as e:
        logger.error(f"explain_attribution raised; returning prediction without explanation: {e}")
    return result



def _is_internal_relay_request(request: Request) -> bool:
    if request.headers.get(INTERNAL_RELAY_HEADER) != INTERNAL_RELAY_VALUE:
        return False
    client_host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(client_host) in INTERNAL_RELAY_NETWORK
    except ValueError:
        return False


@router.get("/shadow/decision", include_in_schema=False)
async def shadow_decision(request: Request):
    """Internal Docker-to-loopback relay for the Nginx shadow hook."""
    if not _is_internal_relay_request(request):
        raise HTTPException(status_code=404, detail="Not found")

    payload = {
        "url": request.headers.get("X-Original-URI", "/"),
        "method": request.headers.get("X-Original-Method", "GET"),
        "body": "",
    }
    try:
        async with httpx.AsyncClient() as client:
            upstream = await client.post(
                f"{ML_SERVICE_URL}/predict-fast",
                json=payload,
                timeout=0.5,
            )
        if upstream.status_code != 200:
            return Response(
                status_code=204,
                headers={"X-WAF-ML-Decision": "unavailable"},
            )
        result = upstream.json()
        decision = "anomaly" if result.get("is_anomaly") else "pass"
        return Response(
            status_code=204,
            headers={
                "X-WAF-ML-Decision": decision,
                "X-WAF-ML-Score": str(result.get("attack_probability", "")),
            },
        )
    except Exception as exc:
        logger.warning("ML shadow relay failed open: %s", exc)
        return Response(
            status_code=204,
            headers={"X-WAF-ML-Decision": "error"},
        )


@router.post("/capture", include_in_schema=False)
async def capture_telemetry_relay(request: Request):
    """Docker-to-loopback relay for privacy-scoped lab telemetry."""
    if not _is_internal_relay_request(request):
        raise HTTPException(status_code=404, detail="Not found")
    body = await request.body()
    headers = {
        "X-Original-Host": request.headers.get("X-Original-Host", ""),
        "X-Original-URI": request.headers.get("X-Original-URI", "/"),
        "X-Original-Method": request.headers.get("X-Original-Method", "GET"),
        "X-Original-Request-ID": request.headers.get("X-Original-Request-ID", ""),
        "Content-Type": request.headers.get("Content-Type", ""),
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ML_SERVICE_URL}/capture",
                content=body,
                headers=headers,
                timeout=0.5,
            )
    except Exception as exc:
        logger.warning("ML capture relay failed open: %s", exc)
    return Response(status_code=204)

@router.post("/predict")
async def predict_anomaly(req: PredictRequest, current_user: dict = Depends(require_viewer_or_above)):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ML_SERVICE_URL}/predict",
                json=req.dict(),
                timeout=10.0
            )
            response.raise_for_status()
            result = response.json()
            return await _attach_explanation(req, result)
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"ML Service error: {e.response.text}")

@router.post("/predict-and-suggest")
async def predict_and_suggest(req: PredictRequest, current_user: dict = Depends(require_viewer_or_above)):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ML_SERVICE_URL}/predict",
                json=req.dict(),
                timeout=10.0
            )
            response.raise_for_status()
            result = response.json()
            result = await _attach_explanation(req, result)

            # If anomaly detected, generate a pending rule
            pending_rule = None
            if result.get("is_anomaly"):
                rule_res = await client.post(
                    f"{ML_SERVICE_URL}/generate-rule",
                    json={
                        "url": req.url,
                        "method": req.method,
                        "body": req.body,
                        "attack_type": "Anomaly Pattern"
                    },
                    timeout=10.0
                )
                if rule_res.status_code == 200:
                    rule_data = rule_res.json()
                    from services.ml_rule_service import MLRuleService
                    rule_service = MLRuleService()
                    pending_rule = rule_service.create_pending_rule(rule_data, created_by="ml-auto")
            
            return {
                "prediction": result,
                "suggested_rule": pending_rule
            }
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"ML Service error: {e.response.text}")
