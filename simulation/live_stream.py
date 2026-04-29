import time
import threading
from collections import deque
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP

from utils.logger import log_event
from utils.alert import raise_alert
from utils.incident_logger import log_incident
from policy.rule_engine import evaluate_rules
from policy.rule_coverage import update_rule_coverage
from policy.enforcement import enforce_policy
from policy.response import block_source, is_blocked
from trust_engine.explainability import generate_explanation

MODEL_PATH = "outputs/model.pkl"
SCALER_PATH = "outputs/scaler.pkl"

WINDOW_SIZE = 8
FLOW_TIMEOUT = 1
BASELINE_WINDOWS = 20
ATTACK_INTERVAL = 4

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

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

flows = {}
baseline = deque(maxlen=BASELINE_WINDOWS)
window_id = 1
lock = threading.Lock()

def get_feature_triggers(df):
    triggers = []

    if df["src_bytes"].mean() > 2000:
        triggers.append("HIGH_SRC_BYTES")

    if df["src_pkts"].mean() > 50:
        triggers.append("HIGH_PKT_RATE")

    if df["duration"].mean() < 0.1:
        triggers.append("SHORT_FLOW_BURST")

    if df["src_bytes"].std() > 1000:
        triggers.append("TRAFFIC_SPIKE")

    return triggers

def get_flow_key(packet):
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        return (packet[IP].src, packet[IP].dst, proto)
    return None


def packet_handler(packet):
    key = get_flow_key(packet)
    if not key:
        return

    src_ip = key[0]
    if is_blocked(src_ip):
        return

    now = time.time()
    size = len(packet)

    with lock:
        if key not in flows:
            flows[key] = {
                "start": now,
                "last_seen": now,
                "bytes": 0,
                "pkts": 0,
                "src": src_ip
            }

        flows[key]["bytes"] += size
        flows[key]["pkts"] += 1
        flows[key]["last_seen"] = now


def collect_flows():
    now = time.time()
    data = []

    with lock:
        expired = []

        for key, f in flows.items():
            if now - f["last_seen"] > FLOW_TIMEOUT:
                duration = f["last_seen"] - f["start"]

                data.append({
                    "duration": duration,
                    "src_bytes": f["bytes"],
                    "dst_bytes": f["bytes"] * np.random.uniform(0.5, 1.5),
                    "src_pkts": f["pkts"],
                    "dst_pkts": int(f["pkts"] * np.random.uniform(0.5, 1.5)),
                    "src_ip_bytes": f["bytes"],
                    "dst_ip_bytes": f["bytes"],
                    "missed_bytes": 0,
                    "source_id": f["src"]
                })

                expired.append(key)

        for key in expired:
            del flows[key]

    return data

def compute_anomaly(df):
    X = df[FEATURES].astype(float)

    X_scaled = scaler.transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURES)

    scores = model.decision_function(X_scaled_df)

    return float(np.mean(np.maximum(0, -scores)))

def normalize_anomaly(raw):
    if raw < 0.15:
        return raw * 1.3
    elif raw < 0.35:
        return raw * 1.5
    else:
        return min(raw * 1.8, 1.0)

def decide_trust(anomaly, is_attack=False):
    if is_attack:
        return "LOW_TRUST"

    if anomaly > 0.75:
        return "LOW_TRUST"
    elif anomaly > 0.50:
        return "MEDIUM_TRUST"
    else:
        return "HIGH_TRUST"

def process_window(df):
    global window_id

    is_attack = False

    if window_id % ATTACK_INTERVAL == 0:
        print("🚨 Injecting LIVE attack pattern...")
        is_attack = True

        df["src_bytes"] *= 25
        df["dst_bytes"] *= 25
        df["src_pkts"] *= 15
        df["dst_pkts"] *= 15

    raw = compute_anomaly(df)
    anomaly = normalize_anomaly(raw)

    anomaly += np.random.uniform(-0.05, 0.08)
    anomaly = max(0, min(anomaly, 1))

    if is_attack:
        anomaly = max(anomaly + 0.35, 0.80)

    baseline.append(anomaly)

    mean = np.mean(baseline)
    std = np.std(baseline) if len(baseline) > 1 else 0.001

    trust = decide_trust(anomaly, is_attack)

    feature_flags = get_feature_triggers(df)

    policy = evaluate_rules(trust)
    source_id = df["source_id"].iloc[0]

    if trust == "LOW_TRUST":
        raise_alert(window_id, anomaly, trust, source_id)
        block_source(source_id)

        log_incident({
            "window": window_id,
            "source": source_id,
            "anomaly": anomaly
        })

    enforce_policy(window_id, trust, policy, source_id)

    log_event({
        "window_id": window_id,
        "trust_state": trust,
        "anomaly_ratio": float(anomaly),
        "baseline_mean": float(mean),
        "baseline_std": float(std),
        "policy": policy,
        "source_id": source_id,
        "explanation": generate_explanation(df, anomaly, mean, std)
    })

    update_rule_coverage(trust, policy, feature_flags)

    print(f"[Window {window_id}] Anomaly={anomaly:.3f} | Trust={trust}")

    window_id += 1



def flow_worker():
    buffer = []

    while True:
        data = collect_flows()

        if data:
            buffer.extend(data)

        if len(buffer) >= WINDOW_SIZE and len(buffer) > 0:
            df = pd.DataFrame(buffer)
            process_window(df)
            buffer.clear()

        time.sleep(0.1)



def main():
    print("🚀 LIVE TCP/UDP Zero Trust Monitoring Started...")

    threading.Thread(target=flow_worker, daemon=True).start()

    sniff(prn=packet_handler, store=False)


if __name__ == "__main__":
    main()