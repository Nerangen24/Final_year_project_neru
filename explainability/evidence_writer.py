import json
import os

BASE_DIR = "results/windows"

def write_window_evidence(
    window_id,
    trust_state,
    anomaly_ratio,
    baseline_mean,
    baseline_std,
    feature_explanation,
    enforced_policy
):
    os.makedirs(BASE_DIR, exist_ok=True)

    data = {
        "window_id": window_id,
        "trust_state": trust_state,
        "anomaly_ratio": anomaly_ratio,
        "baseline_mean": baseline_mean,
        "baseline_std": baseline_std,
        "top_features": feature_explanation,
        "policy": enforced_policy
    }

    path = f"{BASE_DIR}/window_{window_id}.json"

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    return path
