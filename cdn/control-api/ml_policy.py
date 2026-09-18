# Gen3 roadmap 1.3 -- Adaptive Action Policy.
#
# Maps the ML shadow decision (roadmap 1.2, dashboard/backend/api/ml.py's
# `shadow_decision`) to a shield outcome ("pass" | "challenge" | "block"),
# consumed by otp_engine.shield_access as a third branch alongside
# captcha/otp. Global, not per-origin -- ML enforcement is a cross-cutting
# policy, unlike captcha/otp's per-origin opt-in.
#
# Off by default and stays off until a model artifact passes the roadmap's
# own promotion gate (Benign Recall >=98.5%, Attack Recall >=85-90%) -- see
# dashboard/backend/services/settings_service.py's DEFAULT_SETTINGS comment
# and WAF_GEN3_ROADMAP.md Phase 2. The `ml_enforcement_enabled` flag is
# read fresh from Redis on every call (no in-process caching) so flipping it
# off is an immediate, one-write rollback with no control-api restart.
import json
import logging
import os

import httpx

from captcha_engine import _redis

logger = logging.getLogger(__name__)

REDIS_KEY = "waf:ml:policy"

# Reuses dashboard-backend's existing shadow-decision relay as-is (same
# endpoint nginx's dead 1.2 mirror hook targeted) -- no new backend route.
# It already fails open (204 + X-WAF-ML-Decision: error/unavailable) and
# already gates callers by X-Internal-ML-Relay + a 172.16.0.0/12 source
# check that control-api's own docker-bridge IP satisfies.
RELAY_URL = os.getenv(
    "ML_SHADOW_RELAY_URL",
    "http://host.docker.internal:8000/api/ml/shadow/decision",
)
RELAY_HEADER_NAME = "X-Internal-ML-Relay"
RELAY_HEADER_VALUE = "nginx-shadow-v1"

DEFAULT_POLICY = {
    "ml_enforcement_enabled": False,
    "ml_block_threshold": 0.95,
    "ml_challenge_threshold": 0.70,
}


def _policy() -> dict:
    try:
        raw = _redis().get(REDIS_KEY)
        if not raw:
            return DEFAULT_POLICY
        data = json.loads(raw)
        return {**DEFAULT_POLICY, **data}
    except Exception as exc:
        logger.warning("ML policy read failed, defaulting to disabled: %s", exc)
        return DEFAULT_POLICY


async def ml_access_decision(request) -> str:
    """Returns "pass" | "challenge" | "block".

    Fails open to "pass" on any error or timeout -- matches this project's
    fail-open convention already used by rate-limit, captcha, and otp in the
    same shield chain (see otp_engine.shield_access).
    """
    policy = _policy()
    if not policy.get("ml_enforcement_enabled"):
        return "pass"  # short-circuits before any HTTP call: zero added
        # latency for the default (and currently only) production state.

    headers = {
        RELAY_HEADER_NAME: RELAY_HEADER_VALUE,
        "X-Original-URI": request.headers.get("x-original-uri", "/"),
        "X-Original-Method": request.headers.get("x-original-method", "GET"),
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(RELAY_URL, headers=headers, timeout=0.5)
        score_raw = resp.headers.get("X-WAF-ML-Score", "")
        score = float(score_raw) if score_raw else 0.0
    except Exception as exc:
        logger.warning("ML shadow relay call failed, fail-open pass: %s", exc)
        return "pass"

    if score >= float(policy.get("ml_block_threshold", DEFAULT_POLICY["ml_block_threshold"])):
        return "block"
    if score >= float(policy.get("ml_challenge_threshold", DEFAULT_POLICY["ml_challenge_threshold"])):
        return "challenge"
    return "pass"
