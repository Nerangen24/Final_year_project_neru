import json
import os
from datetime import datetime

LOG_DIR = "logs"
WINDOWS_DIR = "results/windows"
COVERAGE_FILE = "results/rule_coverage.json"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(WINDOWS_DIR, exist_ok=True)
os.makedirs("results", exist_ok=True)


def log_event(data):
    data["timestamp"] = datetime.utcnow().isoformat()

    trust = data.get("trust_state", "HIGH_TRUST")
    data["prediction"] = 1 if trust == "LOW_TRUST" else 0

    log_file = os.path.join(LOG_DIR, "events.jsonl")

    with open(log_file, "a") as f:
        f.write(json.dumps(data) + "\n")

    window_id = data.get("window_id")

    if window_id is not None:
        window_file = os.path.join(
            WINDOWS_DIR,
            f"window_{int(window_id):03d}.json"
        )

        with open(window_file, "w") as f:
            json.dump(data, f, indent=2)

    update_feature_triggers(data)


def update_feature_triggers(data):
    if os.path.exists(COVERAGE_FILE):
        with open(COVERAGE_FILE, "r") as f:
            coverage = json.load(f)
    else:
        coverage = {
            "rules": {},
            "trust_states": {},
            "feature_triggers": {}
        }

    triggers = data.get("explanation", [])

    for t in triggers:
        coverage["feature_triggers"][t] = coverage["feature_triggers"].get(t, 0) + 1

    with open(COVERAGE_FILE, "w") as f:
        json.dump(coverage, f, indent=4)