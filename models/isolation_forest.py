import pandas as pd
from sklearn.ensemble import IsolationForest

DATA_FILE = "../outputs/sampled_data.csv"
OUTPUT_FILE = "../outputs/anomaly_scores.csv"

if __name__ == "__main__":
    # Load data
    df = pd.read_csv(DATA_FILE)

    # Keep a clean copy of features
    X = df.copy()

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X)

    # Generate anomaly scores and flags
    anomaly_scores = model.decision_function(X)
    anomaly_flags = model.predict(X)

    # Attach results
    df["anomaly_score"] = anomaly_scores
    df["anomaly_flag"] = anomaly_flags

    # Save output
    df.to_csv(OUTPUT_FILE, index=False)
    print("Anomaly detection completed successfully.")
