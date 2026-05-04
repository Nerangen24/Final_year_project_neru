import json
import os
from datetime import datetime

LOG_DIR = "logs"
WINDOWS_DIR = "results/windows"
COVERAGE_FILE = "results/rule_coverage.json"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(WINDOWS_DIR, exist_ok=True)
os.makedirs("results", exist_ok=True)


def load_coverage():
    if os.path.exists(COVERAGE_FILE):
        with open(COVERAGE_FILE, "r") as f:
            return json.load(f)
    return {
        "rules": {},
        "trust_states": {},
        "feature_triggers": {}
    }


def save_coverage(data):
    with open(COVERAGE_FILE, "w") as f:
        json.dump(data, f, indent=4)


def log_event(data):
    data["timestamp"] = datetime.utcnow().isoformat()

    trust = data.get("trust_state", "HIGH_TRUST")
    data["prediction"] = 1 if trust == "LOW_TRUST" else 0

    if trust == "LOW_TRUST":
        rule = "RATE_LIMIT_SEVERE"
    elif trust == "MEDIUM_TRUST":
        rule = "RATE_LIMIT_MODERATE"
    else:
        rule = "ALLOW"

    data["rule"] = rule

    with open(os.path.join(LOG_DIR, "events.jsonl"), "a") as f:
        f.write(json.dumps(data) + "\n")

    window_id = data.get("window_id")

    if window_id is not None:
        with open(os.path.join(WINDOWS_DIR, f"window_{int(window_id):03d}.json"), "w") as f:
            json.dump(data, f, indent=2)

    update_coverage(data)


def update_coverage(data):
    coverage = load_coverage()

    trust = data.get("trust_state")
    if trust:
        coverage["trust_states"][trust] = coverage["trust_states"].get(trust, 0) + 1

    rule = data.get("rule")
    if rule:
        coverage["rules"][rule] = coverage["rules"].get(rule, 0) + 1

    triggers = data.get("explanation", [])
    for t in triggers:
        coverage["feature_triggers"][t] = coverage["feature_triggers"].get(t, 0) + 1

    save_coverage(coverage)
