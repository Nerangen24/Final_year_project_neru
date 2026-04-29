import pandas as pd
import time
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest
from models.model_manager import load_model

from trust_engine.trust_logic import decide_trust
from policy.rule_engine import evaluate_rules
from policy.enforcement import enforce_policy
from policy.rule_coverage import record_policy, flush_coverage
from explainability.feature_analyzer import analyze_features
from explainability.evidence_writer import write_window_evidence

DATA_FILE = "outputs/attack_data.csv"
WINDOW_SIZE = 1000
BASELINE_WINDOWS = 20
SLEEP_TIME = 0.2

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

    print("Loading data...")
    df = pd.read_csv(DATA_FILE)

    X = df[FEATURES]

    print("Training Isolation Forest...")
    model = load_model()
    print("\nStarting adaptive streaming inference...\n")
    baseline = deque(maxlen=BASELINE_WINDOWS)

    start = 0
    window_id = 1

    while start < len(X):
        window = X.iloc[start:start + WINDOW_SIZE]
        flags = model.predict(window)
        anomaly_ratio = (flags == -1).sum() / len(flags)
        baseline.append(anomaly_ratio)
        mean = np.mean(baseline)
        std = np.std(baseline) if len(baseline) > 1 else 0.0
        trust_state = decide_trust(anomaly_ratio, mean, std)

        print(
            f"Window {window_id:03d} | "
            f"Anomaly={anomaly_ratio:.2%} | "
            f"μ={mean:.2%}, σ={std:.2%}"
        )

        baseline_df = X.iloc[
            max(0, start - WINDOW_SIZE * BASELINE_WINDOWS): start
        ]

        explanation = None

        if trust_state in ["MEDIUM_TRUST", "LOW_TRUST"] and len(baseline_df) > 0:

            explanation = analyze_features(window, baseline_df)

            policy = evaluate_rules(
                trust_state=trust_state,
                feature_explanation=explanation
            )

            evidence_path = write_window_evidence(
                window_id=window_id,
                trust_state=trust_state,
                anomaly_ratio=anomaly_ratio,
                baseline_mean=mean,
                baseline_std=std,
                feature_explanation=explanation,
                enforced_policy=policy
            )

            print(f" → Evidence saved to {evidence_path}")

        else:
            policy = evaluate_rules(trust_state)

        record_policy(
            trust_state=trust_state,
            policy=policy,
            feature_explanation=explanation
        )

        enforce_policy(window_id, trust_state, policy)

        start += WINDOW_SIZE
        window_id += 1
        time.sleep(SLEEP_TIME)

    flush_coverage()
    print("\n✔ Rule coverage report written to results/rule_coverage.json")


if __name__ == "__main__":
    main()
