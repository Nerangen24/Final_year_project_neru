import pandas as pd
import time
from sklearn.ensemble import IsolationForest

DATA_FILE = "../outputs/sampled_data.csv"
WINDOW_SIZE = 1000
SLEEP_TIME = 0.3

def trust_from_ratio(ratio):
    if ratio > 0.10:
        return "LOW_TRUST"
    elif ratio > 0.05:
        return "MEDIUM_TRUST"
    else:
        return "HIGH_TRUST"

if __name__ == "__main__":
    print("Loading historical data...")
    df = pd.read_csv(DATA_FILE)

    print("Training Isolation Forest (offline)...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    model.fit(df)

    print("\nStarting streaming inference...\n")

    start = 0
    window_id = 1

    while start < len(df):
        window = df.iloc[start : start + WINDOW_SIZE]

        flags = model.predict(window)
        anomaly_ratio = (flags == -1).sum() / len(flags)

        trust_state = trust_from_ratio(anomaly_ratio)

        print(
            f"Window {window_id:03d} | "
            f"Anomaly Ratio: {anomaly_ratio:.2%} | "
            f"Trust State: {trust_state}"
        )

        start += WINDOW_SIZE
        window_id += 1
        time.sleep(SLEEP_TIME)
