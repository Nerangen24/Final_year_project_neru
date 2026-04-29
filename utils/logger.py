import json
import os
from datetime import datetime

LOG_DIR = "logs"
WINDOWS_DIR = "results/windows"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(WINDOWS_DIR, exist_ok=True)


def log_event(data):
    data["timestamp"] = datetime.utcnow().isoformat()

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