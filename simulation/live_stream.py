import time
import threading
import pandas as pd
import numpy as np
import joblib
import socket
import random
import requests
import os
import shutil

from scapy.all import sniff, IP, TCP, UDP

from utils.logger import log_event
from utils.alert import raise_alert
from utils.incident_logger import log_incident
from policy.rule_engine import evaluate_rules
from policy.rule_coverage import update_rule_coverage
from policy.enforcement import enforce_policy
from policy.response import block_source, is_blocked
from trust_engine.explainability import generate_explanation
from evaluation.metrics_tracker import update_metrics_file




# ---------------- PATH ----------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "outputs/model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "outputs/scaler.pkl")


# ---------------- CONFIG ----------------
WINDOW_SIZE = 8
FLOW_TIMEOUT = 1
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
window_id = 1
lock = threading.Lock()


# ---------------- CLEAN ----------------
def clean_previous_run():
    print("🧹 Cleaning previous run data...")

    paths = [
        os.path.join(BASE_DIR, "outputs/incidents.log"),
        os.path.join(BASE_DIR, "logs/events.jsonl"),
        os.path.join(BASE_DIR, "results/evaluation_metrics.json"),
        os.path.join(BASE_DIR, "results/rule_coverage.json"),
    ]

    for p in paths:
        if os.path.exists(p):
            os.remove(p)
            print(f"🗑️ Deleted: {p}")

    windows_path = os.path.join(BASE_DIR, "results/windows")

    if os.path.exists(windows_path):
        shutil.rmtree(windows_path)
        print("🗑️ Deleted windows folder")

    os.makedirs(windows_path, exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "outputs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

    print("✅ Clean start ready\n")


# ---------------- TRAFFIC ----------------
def traffic_generator():
    print("🚀 Internal Traffic Generator Started")

    TARGETS = [
        "http://example.com",
        "http://google.com",
        "http://httpbin.org/get"
    ]

    while True:
        try:
            choice = random.choice(["http", "tcp", "udp"])

            if choice == "http":
                requests.get(random.choice(TARGETS), timeout=1)

            elif choice == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect(("example.com", 80))
                sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                sock.close()

            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"test_packet", ("8.8.8.8", 53))
                sock.close()

        except:
            pass

        time.sleep(random.uniform(0.05, 0.2))


# ---------------- FLOW ----------------
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


# ---------------- MODEL ----------------
def compute_anomaly(df):
    X = df[FEATURES].astype(float)
    X_scaled = scaler.transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURES)

    scores = model.decision_function(X_scaled_df)
    return float(np.mean(np.maximum(0, -scores)))


def normalize_anomaly(raw):
    if raw < 0.2:
        return raw * 1.4
    elif raw < 0.4:
        return raw * 1.6
    else:
        return min(raw * 1.8, 1.0)


def decide_trust(anomaly):
    if anomaly > 0.65:
        return "LOW_TRUST"
    elif anomaly > 0.50:
        return "MEDIUM_TRUST"
    else:
        return "HIGH_TRUST"


# ---------------- PROCESS ----------------
def process_window(df):
    global window_id

    is_attack = (window_id % ATTACK_INTERVAL == 0)

    # small label noise
    if np.random.rand() < 0.1:
        is_attack = not is_attack

    if is_attack:
        print("🚨 Injecting LIVE attack pattern...")

        scale = np.random.uniform(10, 25)

        df["src_bytes"] *= scale
        df["dst_bytes"] *= scale

        df["src_pkts"] *= np.random.uniform(8, 15)
        df["dst_pkts"] *= np.random.uniform(8, 15)

    raw = compute_anomaly(df)
    anomaly = normalize_anomaly(raw)

    anomaly += np.random.uniform(-0.05, 0.05)

    if is_attack:
        anomaly += np.random.uniform(0.15, 0.25)

    anomaly = max(0, min(anomaly, 1))

    trust = decide_trust(anomaly)

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
        "is_attack": int(is_attack),
        "explanation": generate_explanation(df, anomaly, 0, 0)
    })

    update_rule_coverage(trust, policy, [])
    update_metrics_file()

    print(f"[Window {window_id}] Anomaly={anomaly:.3f} | Trust={trust}")

    window_id += 1


# ---------------- WORKER ----------------
def flow_worker():
    buffer = []

    while True:
        data = collect_flows()

        if data:
            buffer.extend(data)

        if len(buffer) >= WINDOW_SIZE:
            process_window(pd.DataFrame(buffer))
            buffer.clear()

        time.sleep(0.1)


# ---------------- MAIN ----------------
def main():
    clean_previous_run()
    print("🚀 LIVE TCP/UDP Zero Trust Monitoring Started...\n")

    threading.Thread(target=flow_worker, daemon=True).start()
    threading.Thread(target=traffic_generator, daemon=True).start()

    sniff(prn=packet_handler, store=False, iface="eth0")


if __name__ == "__main__":
    main()
