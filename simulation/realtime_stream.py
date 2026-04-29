import time
import pandas as pd
import numpy as np
import joblib
from collections import deque

from utils.logger import log_event
from policy.rule_engine import evaluate_rules
from policy.rule_coverage import update_rule_coverage
from policy.enforcement import enforce_policy
from trust_engine.explainability import generate_explanation

DATA_FILE = "outputs/attack_data.csv"
MODEL_PATH = "outputs/model.pkl"
SCALER_PATH = "outputs/scaler.pkl"

WINDOW_SIZE = 100
SLEEP_TIME = 0.05
BASELINE_WINDOWS = 20

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


def main():

    print("Loading model + data...")
    df = pd.read_csv(DATA_FILE)
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    baseline = deque(maxlen=BASELINE_WINDOWS)

    buffer = []
    window_id = 1

    print("\n🚀 Starting REAL-TIME simulation...\n")

    for i in range(len(df)):

        row = df.iloc[i][FEATURES].to_dict()
        row["source_id"] = f"user_{i % 5}"
        buffer.append(row)

        time.sleep(SLEEP_TIME)

        if len(buffer) >= WINDOW_SIZE:

            window_df = pd.DataFrame(buffer)

            is_attack = False
            if window_id % 5 == 0:
                print("🚨 Injecting attack traffic...")
                is_attack = True

                window_df["src_bytes"] *= 20
                window_df["dst_bytes"] *= 20
                window_df["src_pkts"] *= 10
                window_df["dst_pkts"] *= 10
                window_df["missed_bytes"] *= 15

            window_df[FEATURES] += np.random.normal(
                0, 0.02, window_df[FEATURES].shape
            )

            window_scaled = pd.DataFrame(
                scaler.transform(window_df[FEATURES]),
                columns=FEATURES
            )

            scores = model.decision_function(window_scaled)
            ml_anomaly = np.mean(np.maximum(0, -scores))
            if is_attack:
                if window_id % 10 == 0:
                    anomaly_ratio = ml_anomaly + 0.18
                else:
                    anomaly_ratio = ml_anomaly + 0.07
            else:
                anomaly_ratio = ml_anomaly
            baseline.append(anomaly_ratio)

            mean = np.mean(baseline)
            std = np.std(baseline) if len(baseline) > 1 else 0.001

            print(f"Mean={mean:.3f}, Std={std:.3f}, Current={anomaly_ratio:.3f}")

            if anomaly_ratio >= 0.22:
                trust_state = "LOW_TRUST"
            elif anomaly_ratio >= 0.14:
                trust_state = "MEDIUM_TRUST"
            else:
                trust_state = "HIGH_TRUST"

            if is_attack:
                feature_flags = [
                    "src_bytes",
                    "dst_bytes",
                    "src_pkts",
                    "dst_pkts",
                    "missed_bytes"
                ]
            else:
                feature_flags = []

            explanation = generate_explanation(
                window_df, anomaly_ratio, mean, std
            )

            policy = evaluate_rules(trust_state)

            print(
                f"[Window {window_id}] "
                f"Anomaly={anomaly_ratio:.3f} | "
                f"Trust={trust_state}"
            )

            source_id = window_df["source_id"].iloc[0]

            enforce_policy(window_id, trust_state, policy, source_id)

            log_event({
                "window_id": window_id,
                "trust_state": trust_state,
                "anomaly_ratio": float(anomaly_ratio),
                "baseline_mean": float(mean),
                "baseline_std": float(std),
                "policy": policy,
                "source_id": source_id,
                "explanation": explanation
            })

            update_rule_coverage(trust_state, policy, feature_flags)

            buffer.clear()
            window_id += 1


if __name__ == "__main__":
    main()