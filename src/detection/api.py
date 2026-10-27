
from typing import Literal

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.detection.predictor import MalwarePredictor, EXPECTED_FEATURES

app = FastAPI(
    title="MLWINT Malware Detection API",
    description="Inference API for trained EMBER malware classifiers.",
    version="1.0.0",
)

MODEL_NAMES = ("lightgbm", "xgboost", "ensemble")
_predictors = {}


class PredictRequest(BaseModel):
    model: Literal["lightgbm", "xgboost", "ensemble"] = "lightgbm"
    features: list[float] = Field(
        min_length=EXPECTED_FEATURES,
        max_length=EXPECTED_FEATURES,
        description="One EMBER feature vector containing exactly 2,381 values.",
    )
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class PredictResponse(BaseModel):
    model: str
    malicious_probability: float
    prediction: Literal["benign", "malicious"]
    threshold: float


def get_predictor(model_name: str) -> MalwarePredictor:
    if model_name not in _predictors:
        try:
            _predictors[model_name] = MalwarePredictor(model_name)
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Model could not be loaded: {exc}",
            ) from exc
    return _predictors[model_name]


@app.get("/health")
def health():
    return {"status": "ok", "service": "MLWINT"}


@app.get("/models")
def models():
    return {
        "default": "lightgbm",
        "available": list(MODEL_NAMES),
    }


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    if not np.isfinite(request.features).all():
        raise HTTPException(
            status_code=422,
            detail="Features must contain only finite numeric values.",
        )

    predictor = get_predictor(request.model)

    try:
        probability = float(
            predictor.predict_proba(
                np.asarray(request.features, dtype=np.float32)
            )[0]
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return PredictResponse(
        model=request.model,
        malicious_probability=probability,
        prediction=(
            "malicious" if probability >= request.threshold else "benign"
        ),
        threshold=request.threshold,
    )
