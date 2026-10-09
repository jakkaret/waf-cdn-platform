import os
import sys
import hmac
import json
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.feature_engineering import extract_features_from_request, feature_columns_for_model
from ml.capture_telemetry import capture_request
from ml.auto_rule_generator import generate_pending_rule
from ml.attribution import build_attribution_response
from ml.onnx_inference import OnnxWafInference

# Docs/12-Development-Guide.md T13: the project's stated accuracy target.
ACCURACY_TARGET = 0.85


def accuracy_meets_target(eval_results: dict, target: float = ACCURACY_TARGET) -> bool:
    """Whether the real, measured evaluation accuracy reaches `target`.

    Fails closed: no evaluation data is not evidence of passing. This
    replaces a hardcoded `True` that /health returned regardless of the
    actual eval_accuracy figure next to it -- verified live on Main,
    2026-09-01, returning the self-contradicting pair
    accuracy_target_passed: true, eval_accuracy: 0.8047 (0.8047 < 0.85).
    """
    accuracy = eval_results.get("metrics", {}).get("accuracy")
    if accuracy is None:
        return False
    return accuracy >= target


BASE_DIR = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE_DIR, "models")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_waf.joblib")
ISO_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_waf.joblib")
RF_ONNX_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_waf.onnx")
EVAL_RESULTS_PATH = os.path.join(MODELS_DIR, "eval_results.json")
# Gen 3 model (ml/train_final_gen3.py). Optional and shadow-only: it is not
# promoted (gate 3.1-G.0 not passed), so it scores requests but never decides.
# The ONNX export is preferred (plain data, onnxruntime only); the joblib is the fallback.
# Default: F-noopenappsec (gen3-final-f-noopenappsec-20261002-153004, CSIC + SR-BH only),
# so the open-appsec benchmark stays unseen data. The older F-canon2 is gen3_f_model.onnx.
GEN3_ONNX_PATH = os.environ.get("WAF_GEN3_ONNX_PATH", os.path.join(MODELS_DIR, "gen3", "gen3_f_noopenappsec.onnx"))
GEN3_MODEL_PATH = os.environ.get("WAF_GEN3_MODEL_PATH", os.path.join(MODELS_DIR, "gen3", "gen3_f_noopenappsec.joblib"))
# Engine behind /predict-fast (the Nginx shadow hook): "rf" (13-feature RandomForest
# ONNX, default) or "gen3" (Gen 3 model). Shadow only while ml_enforcement_enabled is off.
FAST_ENGINE = os.environ.get("WAF_FAST_ENGINE", "rf").strip().lower()
# Shared secret for a remote ML host (deploy/azure-ml). Unset = no check, as on
# the VPS where the API listens on 127.0.0.1 only.
API_TOKEN = os.environ.get("WAF_ML_API_TOKEN", "")
TOKEN_HEADER = "X-WAF-ML-Token"
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

app = FastAPI(
    title="WAF Anomaly Detection & Intelligence Dashboard API",
    description="High-Accuracy ML API & Auto WAF Rule Generation",
    version="2.1.0"
)


@app.middleware("http")
async def require_token(request: Request, call_next):
    """Every path (including /health and the docs) needs the token when WAF_ML_API_TOKEN is set."""
    if API_TOKEN and not hmac.compare_digest(request.headers.get(TOKEN_HEADER, "").encode(), API_TOKEN.encode()):
        return JSONResponse(status_code=401, content={"detail": "invalid or missing ML API token"})
    return await call_next(request)

rf_model = None
iso_model = None
fast_engine = None
fast_engine_error = None
eval_results = {}
gen3_model = None
gen3_error = None


def load_gen3_model(path=GEN3_MODEL_PATH, onnx_path=GEN3_ONNX_PATH):
    """(model, error). ONNX first, then joblib. Never raises: a missing file or
    libinjection must not stop the API."""
    errors = []
    if os.path.exists(onnx_path):
        try:
            from ml.gen3_onnx import Gen3OnnxModel  # needs onnxruntime + libinjection
            return Gen3OnnxModel(onnx_path), None
        except Exception as exc:
            errors.append(f"onnx: {type(exc).__name__}: {exc}")
    if os.path.exists(path):
        try:
            import ml.gen3_model  # noqa: F401  (class definition for unpickling; needs libinjection)
            # joblib.load executes a pickle: only load artifacts produced by
            # ml/train_final_gen3.py from this repository.
            return joblib.load(path), "; ".join(errors) or None
        except Exception as exc:
            errors.append(f"joblib: {type(exc).__name__}: {exc}")
    return None, "; ".join(errors) or "Gen 3 model artifact is missing"


@app.on_event("startup")
def startup_event():
    global rf_model, iso_model, fast_engine, fast_engine_error, eval_results, gen3_model, gen3_error
    if os.path.exists(RF_MODEL_PATH):
        rf_model = joblib.load(RF_MODEL_PATH)
        print(f"[+] Loaded Random Forest Model from {RF_MODEL_PATH}")
    
    if os.path.exists(ISO_MODEL_PATH):
        iso_model = joblib.load(ISO_MODEL_PATH)
        print(f"[+] Loaded Isolation Forest Model from {ISO_MODEL_PATH}")

    if os.path.exists(RF_ONNX_MODEL_PATH):
        try:
            fast_engine = OnnxWafInference(MODELS_DIR)
            print(f"[+] Loaded ONNX inline engine from {RF_ONNX_MODEL_PATH}")
        except Exception as exc:
            fast_engine_error = str(exc)
            print(f"[!] ONNX inline engine unavailable: {exc}")
    else:
        fast_engine_error = "ONNX model artifact is missing"

    if os.path.exists(EVAL_RESULTS_PATH):
        with open(EVAL_RESULTS_PATH, "r", encoding="utf-8") as f:
            eval_results = json.load(f)
        print(f"[+] Loaded evaluation results from {EVAL_RESULTS_PATH}")

    gen3_model, gen3_error = load_gen3_model()
    if gen3_model is not None:
        print(f"[+] Loaded Gen 3 shadow model ({gen3_model.runtime})")
    if gen3_error:
        print(f"[!] Gen 3 model: {gen3_error}")

class PredictionRequest(BaseModel):
    url: str
    method: str = "GET"
    body: str = ""

class RuleGenerateRequest(BaseModel):
    url: str
    method: str = "GET"
    body: str = ""
    attack_type: str = "Anomaly Pattern"

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "models_loaded": {
            "random_forest": rf_model is not None,
            "isolation_forest": iso_model is not None
        },
        "onnx_inline": {
            "loaded": fast_engine is not None,
            "error": fast_engine_error
        },
        "gen3_shadow": {
            "loaded": gen3_model is not None,
            "runtime": getattr(gen3_model, "runtime", None),
            "error": gen3_error,
            "feature_set": getattr(gen3_model, "card", {}).get("feature_set") if gen3_model else None,
        },
        "fast_engine": FAST_ENGINE,
        "accuracy_target_passed": accuracy_meets_target(eval_results),
        "eval_accuracy": eval_results.get("metrics", {}).get("accuracy")
    }

@app.get("/eval-results")
def get_eval_results():
    if not eval_results and os.path.exists(EVAL_RESULTS_PATH):
        with open(EVAL_RESULTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    if not eval_results:
        raise HTTPException(status_code=404, detail="Evaluation results not found.")
    return eval_results

def fast_engine_ready() -> bool:
    return (gen3_model if FAST_ENGINE == "gen3" else fast_engine) is not None


def fast_predict(url: str, method: str = "GET", body: str = "") -> dict:
    """/predict-fast result from the engine chosen by WAF_FAST_ENGINE (same response keys)."""
    if FAST_ENGINE != "gen3":
        return fast_engine.predict(url=url, method=method, body=body)
    result = gen3_model.predict(method=method, url=url, body=body)
    return {
        "is_anomaly": bool(result["is_attack"]),
        "attack_probability": result["attack_probability"],
        "anomaly_score": None,
        "detector": f"gen3_f_{gen3_model.runtime}",
        "status": "ANOMALY_DETECTED" if result["is_attack"] else "PASS",
        "threshold": result["threshold"],
        "feature_set": result["feature_set"],
    }


@app.post("/predict-fast")
def predict_fast(req: PredictionRequest):
    """Low-latency ONNX prediction without attribution or Isolation Forest."""
    if not fast_engine_ready():
        raise HTTPException(503, detail=f"fast engine '{FAST_ENGINE}' is not available")
    return fast_predict(url=req.url, method=req.method, body=req.body)

@app.get("/predict-fast/decision", include_in_schema=False)
def predict_fast_decision(request: Request):
    """Shadow-only Nginx hook; always fails open and never enforces policy."""
    uri = request.headers.get("x-original-uri", "/")
    method = request.headers.get("x-original-method", "GET")
    if not fast_engine_ready():
        return Response(
            status_code=204,
            headers={"X-WAF-ML-Decision": "unavailable"},
        )
    try:
        result = fast_predict(url=uri, method=method, body="")
        decision = "anomaly" if result.get("is_anomaly") else "pass"
        return Response(
            status_code=204,
            headers={
                "X-WAF-ML-Decision": decision,
                "X-WAF-ML-Score": str(result.get("attack_probability", "")),
            },
        )
    except Exception as exc:
        print(f"[!] ONNX shadow decision failed, failing open: {exc}")
        return Response(
            status_code=204,
            headers={"X-WAF-ML-Decision": "error"},
        )


@app.post("/predict-gen3")
def predict_gen3(req: PredictionRequest):
    """Gen 3 score for one request, shadow only: reports, never enforces.

    The model is not promoted (gate 3.1-G.0 passed 3/5), so `is_attack` is
    advisory; the RandomForest /predict path is unchanged.
    """
    if gen3_model is None:
        raise HTTPException(503, detail=f"Gen 3 model is not available: {gen3_error}")
    try:
        return gen3_model.predict(method=req.method, url=req.url, body=req.body) | {"mode": "shadow"}
    except Exception as exc:
        raise HTTPException(500, detail=f"Gen 3 scoring failed: {type(exc).__name__}")


@app.post("/capture", include_in_schema=False)
async def capture_telemetry_endpoint(request: Request):
    """Internal, fail-open capture endpoint for allowlisted lab hosts only."""
    try:
        body = await request.body()
        capture_request(
            host=request.headers.get("x-original-host", request.headers.get("host", "")),
            method=request.headers.get("x-original-method", "GET"),
            uri=request.headers.get("x-original-uri", "/"),
            request_id=request.headers.get("x-original-request-id", ""),
            content_type=request.headers.get("content-type", ""),
            body=body,
        )
    except Exception as exc:
        print(f"[!] Telemetry capture failed, failing open: {exc}")
    return Response(status_code=204)

@app.post("/predict")
def predict_anomaly(req: PredictionRequest):
    if rf_model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded. Please train the model first.")

    features = extract_features_from_request(
        url=req.url,
        method=req.method,
        body=req.body
    )
    df_feat = pd.DataFrame([features])[feature_columns_for_model(rf_model)]

    rf_pred = rf_model.predict(df_feat)[0]
    attack_prob = float(rf_model.predict_proba(df_feat)[0][1])
    iso_score = float(iso_model.decision_function(df_feat)[0]) if iso_model else 0.0

    is_anomaly = bool(rf_pred == 1 or attack_prob > 0.5)

    response = {
        "is_anomaly": is_anomaly,
        "attack_probability": round(attack_prob, 4),
        "anomaly_score": round(iso_score, 4),
        "status": "ANOMALY_DETECTED" if is_anomaly else "PASS",
        "confidence": f"{max(attack_prob, 1 - attack_prob) * 100:.1f}%",
        "features": features
    }

    # Attribution explains the prediction; it must never be able to take
    # detection down with it. If it fails for any reason, log and return
    # the original fields unchanged rather than failing the request.
    try:
        response.update(build_attribution_response(rf_model, df_feat))
    except Exception as exc:
        print(f"[!] Attribution failed, returning prediction without it: {exc}")

    return response

@app.post("/generate-rule")
def generate_waf_rule(req: RuleGenerateRequest):
    """
    Auto-generate a ModSecurity SecRule data for an anomalous payload.
    """
    try:
        return generate_pending_rule(
            url=req.url,
            method=req.method,
            body=req.body,
            attack_type=req.attack_type
        )
    except ValueError as exc:  # pattern unsafe to place in a SecRule: never propose it
        raise HTTPException(status_code=422, detail=str(exc))

# Serve Dashboard static files
if os.path.exists(DASHBOARD_DIR):
    app.mount("/", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
