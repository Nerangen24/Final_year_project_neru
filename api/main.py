import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI
from pydantic import BaseModel

from policy.rule_engine import evaluate_rules
from api.dashboard import router as dashboard_router

app = FastAPI(
    title="Adaptive Zero Trust Engine",
    version="1.0"
)

app.include_router(dashboard_router, prefix="/dashboard")

MODEL_PATH = "outputs/model.pkl"
SCALER_PATH = "outputs/scaler.pkl"

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_pkts",
    "dst_pkts",
    "src_ip_bytes",
    "dst_ip_bytes",
    "missed_bytes"
]


class TrafficInput(BaseModel):
    duration: float
    src_bytes: float
    dst_bytes: float
    src_pkts: float
    dst_pkts: float
    src_ip_bytes: float
    dst_ip_bytes: float
    missed_bytes: float


@app.post("/analyze")
def analyze(data: TrafficInput):

    raw = data.dict()

    X_df = pd.DataFrame([raw])[FEATURES]
    X_scaled = scaler.transform(X_df)

    score = model.decision_function(X_scaled)[0]
    anomaly_ratio = -score

    high_traffic = (
        raw["src_bytes"] > 50000 or
        raw["dst_bytes"] > 50000 or
        raw["src_pkts"] > 1000 or
        raw["dst_pkts"] > 1000
    )

    if anomaly_ratio > 0.25 or high_traffic:
        trust_state = "LOW_TRUST"
    elif anomaly_ratio > 0.15:
        trust_state = "MEDIUM_TRUST"
    else:
        trust_state = "HIGH_TRUST"

    policy = evaluate_rules(trust_state)

    return {
        "trust_state": trust_state,
        "anomaly_ratio": float(anomaly_ratio),
        "policy": policy
    }