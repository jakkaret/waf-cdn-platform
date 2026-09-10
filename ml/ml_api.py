import os
import sys
import json
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.feature_engineering import extract_features_from_request, FEATURE_COLUMNS
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
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

app = FastAPI(
    title="WAF Anomaly Detection & Intelligence Dashboard API",
    description="High-Accuracy ML API & Auto WAF Rule Generation",
    version="2.1.0"
)

rf_model = None
iso_model = None
fast_engine = None
fast_engine_error = None
eval_results = {}

@app.on_event("startup")
def startup_event():
    global rf_model, iso_model, fast_engine, fast_engine_error, eval_results
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

@app.post("/predict-fast")
def predict_fast(req: PredictionRequest):
    """Low-latency RF/ONNX prediction without attribution or Isolation Forest."""
    if fast_engine is None:
        raise HTTPException(503, detail="ONNX inline engine is not available")
    return fast_engine.predict(url=req.url, method=req.method, body=req.body)


@app.post("/predict")
def predict_anomaly(req: PredictionRequest):
    if rf_model is None:
        raise HTTPException(status_code=500, detail="ML model is not loaded. Please train the model first.")

    features = extract_features_from_request(
        url=req.url,
        method=req.method,
        body=req.body
    )
    df_feat = pd.DataFrame([features])[FEATURE_COLUMNS]

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
    res = generate_pending_rule(
        url=req.url,
        method=req.method,
        body=req.body,
        attack_type=req.attack_type
    )
    return res

# Serve Dashboard static files
if os.path.exists(DASHBOARD_DIR):
    app.mount("/", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
