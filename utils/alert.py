import json
import time
import os

ALERT_FILE = "outputs/alerts.json"

def raise_alert(window_id, anomaly, trust, source):

    if anomaly > 0.9:
        severity = "CRITICAL"
    elif anomaly > 0.75:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    alert = {
        "timestamp": time.time(),
        "window": window_id,
        "source": source,
        "anomaly": round(anomaly, 3),
        "trust": trust,
        "severity": severity
    }
    os.makedirs("outputs", exist_ok=True)
    try:
        with open(ALERT_FILE, "r") as f:
            data = json.load(f)
    except:
        data = []
    data.append(alert)
    data = data[-30:]
    with open(ALERT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print("\n🚨 ALERT 🚨")
    print(f"Severity: {severity}")
    print(f"Window: {window_id}")
    print(f"Source: {source}")
    print(f"Anomaly: {anomaly:.3f}")
    print(f"Trust: {trust}")
    print("Action: Immediate investigation required\n")