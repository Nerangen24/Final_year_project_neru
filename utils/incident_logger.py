import json
import os

LOG_FILE = "outputs/incidents.log"

def log_incident(data):
    os.makedirs("outputs", exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")