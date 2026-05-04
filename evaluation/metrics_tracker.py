import os
import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EVENTS_FILE = os.path.join(BASE_DIR, "logs/events.jsonl")
METRICS_FILE = os.path.join(BASE_DIR, "results/evaluation_metrics.json")


def parse_events():
    if not os.path.exists(EVENTS_FILE):
        return []

    events = []
    with open(EVENTS_FILE, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except:
                continue

    return events


def compute_metrics(events):
    if len(events) < 15:
        return None

    y_true = []
    y_pred = []

    for e in events:
        actual = e.get("is_attack", 0)
        anomaly = e.get("anomaly_ratio", 0)

        predicted = 1 if anomaly > 0.65 else 0

        y_true.append(actual)
        y_pred.append(predicted)

    if len(set(y_true)) < 2 or len(set(y_pred)) < 2:
        return None

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "fpr": float(fpr),
        "total_samples": len(y_true)
    }


def update_metrics_file():
    events = parse_events()
    metrics = compute_metrics(events)

    if metrics is None:
        return

    os.makedirs(os.path.join(BASE_DIR, "results"), exist_ok=True)

    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)

    print("📊 Metrics Updated:", metrics)