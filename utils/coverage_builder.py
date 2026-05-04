import json
import os

LOG_FILE = "logs/events.jsonl"
OUT_FILE = "results/rule_coverage.json"


def build_coverage():
    coverage = {
        "rules": {},
        "trust_states": {},
        "feature_triggers": {}
    }

    if not os.path.exists(LOG_FILE):
        return coverage

    with open(LOG_FILE, "r") as f:
        for line in f:
            data = json.loads(line)

            trust = data.get("trust_state")
            if trust:
                coverage["trust_states"][trust] = coverage["trust_states"].get(trust, 0) + 1

            triggers = data.get("explanation", [])
            for t in triggers:
                coverage["feature_triggers"][t] = coverage["feature_triggers"].get(t, 0) + 1

    return coverage


def save():
    data = build_coverage()
    with open(OUT_FILE, "w") as f:
        json.dump(data, f, indent=4)