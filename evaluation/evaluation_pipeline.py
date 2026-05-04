import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

events_file = "logs/events.jsonl"
incidents_file = "outputs/incidents.log"

y_true = []
y_pred = []

attack_windows = set()

# load ground truth
try:
    with open(incidents_file) as f:
        for line in f:
            data = json.loads(line)
            attack_windows.add(int(data["window"]))
except:
    print("No incidents found. Run live stream first.")
    exit()

# load predictions
with open(events_file) as f:
    for line in f:
        data = json.loads(line)

        window = int(data["window_id"])
        pred = int(data.get("prediction", 0))

        actual = 1 if window in attack_windows else 0

        y_true.append(actual)
        y_pred.append(pred)

if len(y_true) == 0:
    print("No data available.")
    exit()

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)

cm = confusion_matrix(y_true, y_pred)

if cm.shape == (2, 2):
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
else:
    tn = fp = fn = tp = fpr = 0

print("\n===== EVALUATION METRICS =====")
print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"FPR       : {fpr:.4f}")
print("\nConfusion Matrix:")
print(cm)