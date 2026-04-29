import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DATA_PATH = "outputs/attack_data.csv"
MODEL_PATH = "outputs/model.pkl"
SCALER_PATH = "outputs/scaler.pkl"

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
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    X = df[FEATURES]

    print("Scaling data...")
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X),
        columns=FEATURES
    )
    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=300,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print("✅ Model + Scaler saved")


if __name__ == "__main__":
    main()