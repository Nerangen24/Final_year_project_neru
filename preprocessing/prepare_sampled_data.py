import os
import random
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from datetime import datetime

DATA_DIR = "../data/ton_iot/Processed_Network_dataset"
OUTPUT_FILE = "../outputs/sampled_data.csv"

NUMERIC_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_pkts",
    "dst_pkts",
    "src_ip_bytes",
    "dst_ip_bytes",
    "missed_bytes"
]

CATEGORICAL_FEATURES = ["proto", "conn_state"]
REQUIRED_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES

CHUNK_SIZE = 100_000
TARGET_SAMPLE_SIZE = 500_000 

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def stream_and_sample():
    sampled_chunks = []
    total_sampled = 0

    log("START streaming & sampling")

    for file in os.listdir(DATA_DIR):
        if not file.endswith(".csv"):
            continue

        path = os.path.join(DATA_DIR, file)
        log(f"Reading {file}")

        for chunk in pd.read_csv(
            path,
            usecols=lambda c: c in REQUIRED_COLUMNS,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):
            # Convert numeric safely
            for col in NUMERIC_FEATURES:
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce")

            chunk.fillna(0, inplace=True)

            # Random sampling from chunk
            remaining = TARGET_SAMPLE_SIZE - total_sampled
            if remaining <= 0:
                break

            frac = min(1.0, remaining / len(chunk))
            sampled = chunk.sample(frac=frac, random_state=42)

            sampled_chunks.append(sampled)
            total_sampled += len(sampled)

            log(f"  sampled {total_sampled:,} rows")

        if total_sampled >= TARGET_SAMPLE_SIZE:
            break

    log(f"FINAL sampled rows = {total_sampled:,}")
    return pd.concat(sampled_chunks, ignore_index=True)


def preprocess(df):
    log("Encoding categorical features")
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

    log("Scaling numeric features")
    scaler = StandardScaler()
    df[NUMERIC_FEATURES] = scaler.fit_transform(df[NUMERIC_FEATURES])

    return df


if __name__ == "__main__":
    df = stream_and_sample()
    df = preprocess(df)

    df.to_csv(OUTPUT_FILE, index=False)
    log(f"Saved sampled ML dataset → {OUTPUT_FILE}")
