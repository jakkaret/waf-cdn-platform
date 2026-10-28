import asyncio
import hmac
import ipaddress
import logging
import os
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from services import ml_gate, ml_verdicts
from services.clickhouse_service import ClickHouseService
from services.rbac import ARCHIVED_ORIGIN_STATUSES, is_origin_admin, require_viewer_or_above
from services.gemini_service import gemini_service
from services.pg_store import OriginNotFound
from services.tenant_service import build_tenant_origin_filter, get_user_origins_and_domains
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["ML Analyst"])
# ML Insights reads (services/ml_verdicts.py); the batch writer uses main.py's instance.
ch = ClickHouseService()


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


class SuggestRequest(PredictRequest):
    # The origin the proposals are for (2026-10-26). Its Owner/Editors review
    # them and an approved one runs for that origin only. Empty = the
    # platform admin's global queue, as before.
    origin_id: Optional[str] = None


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
            res = await client.post(
                f"{ML_CAPTURE_URL}/capture",
                content=body,
                headers=headers,
                timeout=ML_FAST_TIMEOUT,
            )
        # 200 = the Gen 3 verdict of this request (ML Insights); 204 = none.
        if res.status_code == 200:
            ml_verdicts.enqueue(res.json(), body=body)
    except Exception as exc:
        logger.warning("ML capture relay failed open: %s", exc)
    return Response(status_code=204)


def _gate_answer(action: str, score: Optional[float] = None, error: str = "") -> Response:
    headers = {"X-WAF-ML-Action": action}
    if score is not None:
        headers["X-WAF-ML-Score"] = f"{score:.4f}"
    if error:
        headers["X-WAF-ML-Error"] = error
    return Response(status_code=204, headers=headers)


@router.post("/gate", include_in_schema=False)
async def gate_relay(request: Request):
    """Inline gate of an origin in enforce mode (nginx/njs/mlgate.js): scores
    the request with its body and answers the action on X-WAF-ML-Action --
    "block", "challenge" or "pass". X-ML-Gate is the origin's policy from the
    nginx map (services/ml_gate.py). Fails open: any error is "pass"."""
    if not _is_internal_relay_request(request):
        raise HTTPException(status_code=404, detail="Not found")
    policy = ml_gate.parse_policy(request.headers.get("X-ML-Gate", ""))
    if policy is None:
        return _gate_answer("pass", error="no-policy")
    if not ML_CAPTURE_URL:
        return _gate_answer("pass", error="disabled")
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
            res = await client.post(f"{ML_CAPTURE_URL}/capture", content=body, headers=headers,
                                    timeout=ML_FAST_TIMEOUT)
        if res.status_code != 200:
            return _gate_answer("pass", error="unavailable")
        verdict = res.json()
        score = float(verdict["score"])
    except Exception as exc:
        logger.warning("ML gate relay failed open: %s", exc)
        return _gate_answer("pass", error="error")
    action = ml_gate.decide(score, policy)
    ml_gate.remember_action(request.headers.get("X-Original-Request-ID", ""), action)
    ml_verdicts.enqueue({**verdict, "action": action}, body=body)
    return _gate_answer(action, score)


def _insights_scope(current_user: dict, origin: Optional[str]) -> str:
    """The tenant clause of the Logs page (api/logs.py): "1=0" when the caller
    may read nothing, "" for a platform admin's unfiltered view."""
    is_admin = current_user.get("role", "viewer") == "admin"
    _ids, _origins, user_domains = get_user_origins_and_domains(current_user.get("user_id"))
    return build_tenant_origin_filter(origin, user_domains, is_admin)


@router.get("/insights")
async def ml_insights(
    origin: Optional[str] = Query("ALL", description="An origin id, or ALL"),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    min_score: Optional[float] = Query(None, ge=0.0, le=1.0),
    current_user: dict = Depends(require_viewer_or_above),
):
    """Gen 3 scores of the caller's real traffic (shadow, nothing blocked):
    totals, score histogram, timeline, detectors and the newest flagged
    requests. Scoped exactly like the Logs page: an origin's Owner, Editors
    and Viewers see that origin's hosts only."""
    scope = _insights_scope(current_user, origin)
    if scope == "1=0":
        return ml_verdicts.empty_insights(hours)
    if not ch.connected:
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    try:
        out = await asyncio.to_thread(ml_verdicts.insights, ch, scope, hours, limit, min_score)
    except Exception as exc:
        logger.warning("ML insights query failed: %s", exc)
        raise HTTPException(status_code=503, detail="analytics store unavailable")
    await asyncio.to_thread(_mark_proposable, out.get("requests") or [], current_user)
    return out


def _mark_proposable(requests: list, current_user: dict) -> None:
    """Per listed request: origin_id (host map), can_edit (the caller is that
    origin's Owner or an Editor: may read the masked body and propose a rule)
    and can_propose (can_edit, Gen 3 flagged it and the inline gate did not
    already block it -- a rule for a request ML blocks adds nothing)."""
    from api.ml_rules import REVIEW_ROLES, _member_roles
    from services.dynamodb_service import DynamoDBService
    from services.shield_sync import desired_hostmap
    hostmap = desired_hostmap(DynamoDBService()) if requests else {}
    roles = _member_roles(current_user.get("user_id"))
    for r in requests:
        oid = hostmap.get(str(r.get("host") or ""))
        can_edit = bool(oid) and roles.get(oid) in REVIEW_ROLES
        r["origin_id"] = oid
        r["can_edit"] = can_edit
        r["can_propose"] = can_edit and bool(r.get("is_attack")) and r.get("action") != "block"

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
    body = {"url": req.url, "method": req.method, "body": req.body}
    res = await client.post(f"{ML_SERVICE_URL}/predict-gen3", json=body, headers=_ml_headers(), timeout=10.0)
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


def _suggest_origin(origin_id: str, current_user: dict) -> dict:
    """The origin a caller asks proposals for: its Owner or an Editor (the
    people who may approve them), or the platform admin. Checked before the
    quota is spent. 403 for anyone else, whether or not the origin exists."""
    from services.dynamodb_service import DynamoDBService
    origin = DynamoDBService().get_origin_by_id(origin_id)
    live = bool(origin) and origin.get("status") not in ARCHIVED_ORIGIN_STATUSES
    if current_user.get("role") == "admin":
        if not live:
            raise HTTPException(status_code=404, detail="Origin not found")
        return origin
    if not live or not is_origin_admin(origin, current_user.get("user_id")):
        raise HTTPException(status_code=403, detail="Owner or Editor of this origin required")
    return origin


def _queue_proposals(rules: list, origin: Optional[dict], current_user: dict) -> tuple[list, int, int]:
    """(pending rules, created, merged): each proposed rule joins the pending
    rule with the same dedup_key in the same origin's queue, or starts one.
    Never approves anything. Also used by ML Insights' "propose a rule"
    (api/ml_protection.py)."""
    suggested, created, merged = [], 0, 0
    if not rules:
        return suggested, created, merged
    from services.ml_rule_service import MLRuleService
    rule_service = MLRuleService()
    origin_id = str(origin["id"]) if origin else ""
    for rule_data in rules:
        rule_data = {**rule_data,
                     "requested_by": current_user.get("username") or current_user.get("email", ""),
                     "requested_by_id": current_user.get("user_id", ""),
                     # Same label the CVE scan stores (cve_feed.match_cves_to_origins).
                     "origin_id": origin_id,
                     "origin_label": origin.get("label", "") if origin else ""}
        existing = rule_service.find_pending_by_dedup_key(rule_data.get("dedup_key", ""), origin_id)
        if existing:
            suggested.append(rule_service.record_hit(existing, rule_data))
            merged += 1
        else:
            try:
                suggested.append(rule_service.create_pending_rule(rule_data, created_by="ml-auto"))
            except OriginNotFound:   # deleted since the caller's access check
                raise HTTPException(status_code=404, detail="Origin not found")
            created += 1
    return suggested, created, merged


def _own_examples_only(rule: dict, current_user: dict) -> dict:
    """A global pending rule merges proposals from everyone who analysed a
    request without an origin, and its examples carry their URLs and names
    (ml_rule_service._example). A non-admin caller gets back only the
    examples they submitted; the platform admin's queue keeps all of them.
    The stored backtest goes too: an admin ran it over every origin's
    traffic, and its example_paths are other tenants' URL paths."""
    uid = str(current_user.get("user_id") or "")
    mine = [e for e in rule.get("examples") or [] if uid and str(e.get("requested_by_id") or "") == uid]
    own = {k: v for k, v in rule.items() if k != "backtest"}
    return {**own, "examples": mine}


@router.post("/predict-and-suggest")
async def predict_and_suggest(req: SuggestRequest, current_user: dict = Depends(require_viewer_or_above)):
    """Score a request with Gen 3 and queue rule proposals for review (an origin's Owner/Editors, or the platform admin).

    Response: `gen3` (score, threshold, detectors), `suggested_rule` (first
    proposal, or None), `suggested_rules` and `suggestion` = {engine, created,
    merged, reason, origin_id}. `reason` says why nothing was proposed: gen3_not_attack,
    gen3_no_detector (flagged on structural features only), generator_error.
    No Gemini call: Gemini described the RandomForest attribution, which is no longer used here.

    With `origin_id` (2026-10-26) the proposals belong to that origin: the
    caller must be its Owner or an Editor (or the platform admin), they merge
    only into a pending rule of the same origin, and an approved one runs for
    that origin only. Without it they go to the global queue, as before.
    """
    origin_id = str(getattr(req, "origin_id", None) or "").strip()
    origin = _suggest_origin(origin_id, current_user) if origin_id else None
    origin_id = str(origin["id"]) if origin else ""
    _check_suggest_quota(str(current_user.get("user_id") or current_user.get("sub") or "unknown"))
    try:
        async with httpx.AsyncClient() as client:
            # Proposals come from the ML service's own answers only.
            gen3 = await _gen3_verdict(client, req)
            rules, reason = await _proposed_rules(client, req, gen3)

            suggested, created, merged = _queue_proposals(rules, origin, current_user)
            if not origin_id and current_user.get("role") != "admin":
                suggested = [_own_examples_only(r, current_user) for r in suggested]

            return {
                "gen3": gen3,
                "suggested_rule": suggested[0] if suggested else None,
                "suggested_rules": suggested,
                "suggestion": {"engine": "gen3", "created": created, "merged": merged, "reason": reason,
                               "origin_id": origin_id},
            }

    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"ML Service unavailable: {str(e)}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"ML Service error: {e.response.text}")
