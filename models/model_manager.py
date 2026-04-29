import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

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


def load_model():
    print("🔹 Loading trained model...")

    df = pd.read_csv("outputs/sampled_data.csv")

    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURES])

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X)

    return model, scaler