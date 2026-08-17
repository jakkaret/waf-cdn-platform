import httpx
from fastapi import APIRouter, HTTPException, Depends
from services.rbac import require_viewer_or_above
from pydantic import BaseModel

router = APIRouter(prefix="/api/ml", tags=["ML Analyst"])

ML_SERVICE_URL = "http://127.0.0.1:5000"

class PredictRequest(BaseModel):
    url: str
    method: str = "GET"
    body: str = ""

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
            return response.json()
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
