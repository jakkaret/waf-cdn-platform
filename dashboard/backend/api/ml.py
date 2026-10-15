import hmac
import ipaddress
import logging
import os
import httpx
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from services.rbac import require_viewer_or_above
from services.gemini_service import gemini_service
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["ML Analyst"])


def _env_float(name: str, default: float) -> float:
    """A positive float from the environment; a missing or bad value keeps the default
    (a typo in the env file must not stop the backend from starting)."""
    try:
        value = float(os.getenv(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


# The ML service runs on this host by default, or on a separate ML host reached
# over WireGuard (deploy/azure-ml/README.md): set ML_SERVICE_URL to its private
# address and ML_SERVICE_TOKEN to the WAF_ML_API_TOKEN configured there. With
# none of these set, behaviour is unchanged (local service, no token).
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://127.0.0.1:5000").rstrip("/")
ML_SERVICE_TOKEN = os.getenv("ML_SERVICE_TOKEN", "")
ML_TOKEN_HEADER = "X-WAF-ML-Token"
# Budget of the Nginx shadow relay and the capture relay; both fail open beyond it.
ML_FAST_TIMEOUT = _env_float("ML_FAST_TIMEOUT", 0.5)
# Where lab telemetry capture is forwarded. Unset = the ML service; set but empty
# = do not forward at all (keeps production request samples off a remote ML host).
ML_CAPTURE_URL = os.getenv("ML_CAPTURE_URL", ML_SERVICE_URL).rstrip("/")
INTERNAL_RELAY_HEADER = "X-Internal-ML-Relay"
# F-019: shared secret between nginx, control-api and this relay. The old
# value was a constant in the (public) repo; unset now means the relay is off.
INTERNAL_RELAY_SECRET = os.getenv("ML_RELAY_SECRET", "")
INTERNAL_RELAY_NETWORK = ipaddress.ip_network("172.16.0.0/12")

# F-113: any viewer could call predict-and-suggest without limit, each call
# writing a row into the admin approval queue and spending a Gemini
# explanation call. Cap it per user (not per IP: behind Caddy every caller
# shares one remote address).
SUGGEST_LIMIT_PER_HOUR = 20
_suggest_limiter = None


def _check_suggest_quota(user_id: str) -> None:
    global _suggest_limiter
    if _suggest_limiter is None:
        from services.rate_limiter import RedisRateLimiter
        _suggest_limiter = RedisRateLimiter()
    # Fail closed: if the quota cannot be checked (Redis down), refuse rather
    # than reopen the flood this cap exists to stop.
    allowed, _, retry_after = _suggest_limiter.is_allowed(
        f"ml-suggest:{user_id}", SUGGEST_LIMIT_PER_HOUR, 3600, fail_open=False
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rule-suggestion limit reached ({SUGGEST_LIMIT_PER_HOUR}/hour). Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

class PredictRequest(BaseModel):
    url: str
    method: str = "GET"
    body: str = ""


def _ml_headers(extra: dict | None = None) -> dict:
    """Headers for every call to the ML service (the token only when configured)."""
    headers = dict(extra or {})
    if ML_SERVICE_TOKEN:
        headers[ML_TOKEN_HEADER] = ML_SERVICE_TOKEN
    return headers


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
    supplied = request.headers.get(INTERNAL_RELAY_HEADER, "")
    if not INTERNAL_RELAY_SECRET or not hmac.compare_digest(
        supplied.encode(), INTERNAL_RELAY_SECRET.encode()
    ):
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
                headers=_ml_headers(),
                timeout=ML_FAST_TIMEOUT,
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
    if not ML_CAPTURE_URL:
        return Response(status_code=204)
    body = await request.body()
    headers = _ml_headers({
        "X-Original-Host": request.headers.get("X-Original-Host", ""),
        "X-Original-URI": request.headers.get("X-Original-URI", "/"),
        "X-Original-Method": request.headers.get("X-Original-Method", "GET"),
        "X-Original-Request-ID": request.headers.get("X-Original-Request-ID", ""),
        "Content-Type": request.headers.get("Content-Type", ""),
    })
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ML_CAPTURE_URL}/capture",
                content=body,
                headers=headers,
                timeout=ML_FAST_TIMEOUT,
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
                headers=_ml_headers(),
                timeout=10.0
            )
            response.raise_for_status()
            result = response.json()
            return await _attach_explanation(req, result)
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"ML Service error: {e.response.text}")

async def _gen3_verdict(client, req: PredictRequest) -> dict:
    """Gen 3 score for the request (`detectors` = what fired, for display).

    The RandomForest is no longer used here (2026-10-13): without a Gen 3 model
    on the ML host the analyst has nothing to show, so this answers 503 rather
    than falling back to the RF score.
    """
    res = await client.post(f"{ML_SERVICE_URL}/predict-gen3", json=req.dict(), headers=_ml_headers(), timeout=10.0)
    if res.status_code != 200:
        raise HTTPException(status_code=503, detail=f"Gen 3 model unavailable on the ML service ({res.status_code})")
    data = res.json()
    if not isinstance(data, dict) or "is_attack" not in data:
        raise HTTPException(status_code=503, detail="Gen 3 model unavailable on the ML service")
    return data


async def _proposed_rules(client, req: PredictRequest, gen3: dict) -> tuple[list, str]:
    """(rule data list, reason) for one analysed request: Gen3-rules only.

    The Gen 3 model decides whether the request is an attack, and every value
    detector that fired becomes one general rule (merged across requests on
    dedup_key). Measured on the open-appsec set (ml/security_test/
    BENCHMARK_PLAN_OPENAPPSEC.md 14.4) Gen 3 separates far better than the
    RandomForest (ROC-AUC 0.965 vs 0.874), whose rules were a literal of the
    request that matched nothing else. Proposals are never applied on their
    own: an admin approves each one, so using the shadow-only Gen 3 model here
    does not let it enforce anything.
    """
    if not gen3.get("is_attack"):
        return [], "gen3_not_attack"
    body = {"url": req.url, "method": req.method, "body": req.body}
    res = await client.post(f"{ML_SERVICE_URL}/generate-rule-gen3", json=body, headers=_ml_headers(), timeout=10.0)
    if res.status_code != 200:
        logger.warning("generate-rule-gen3 answered %s", res.status_code)
        return [], "generator_error"
    rules = res.json().get("rules") or []
    return rules, "" if rules else "gen3_no_detector"


@router.post("/predict-and-suggest")
async def predict_and_suggest(req: PredictRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Score a request with Gen 3 and queue rule proposals for admin review.

    Response: `gen3` (score, threshold, detectors), `suggested_rule` (first
    proposal, or None), `suggested_rules` and `suggestion` = {engine, created,
    merged, reason}. `reason` says why nothing was proposed: gen3_not_attack,
    gen3_no_detector (flagged on structural features only), generator_error.
    No Gemini call: Gemini described the RandomForest attribution, which is no longer used here.
    """
    _check_suggest_quota(str(current_user.get("user_id") or current_user.get("sub") or "unknown"))
    try:
        async with httpx.AsyncClient() as client:
            # Proposals come from the ML service's own answers only.
            gen3 = await _gen3_verdict(client, req)
            rules, reason = await _proposed_rules(client, req, gen3)

            suggested, created, merged = [], 0, 0
            if rules:
                from services.ml_rule_service import MLRuleService
                rule_service = MLRuleService()
                for rule_data in rules:
                    existing = rule_service.find_pending_by_dedup_key(rule_data.get("dedup_key", ""))
                    if existing:
                        suggested.append(rule_service.record_hit(existing, rule_data))
                        merged += 1
                    else:
                        suggested.append(rule_service.create_pending_rule(rule_data, created_by="ml-auto"))
                        created += 1

            return {
                "gen3": gen3,
                "suggested_rule": suggested[0] if suggested else None,
                "suggested_rules": suggested,
                "suggestion": {"engine": "gen3", "created": created, "merged": merged, "reason": reason},
            }

    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"ML Service error: {e.response.text}")
