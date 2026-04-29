import json
import os
from fastapi import APIRouter

router = APIRouter()

RESULTS_DIR = "results/windows"
COVERAGE_FILE = "results/rule_coverage.json"


@router.get("/windows")
def get_windows():
    data = []

    if not os.path.exists(RESULTS_DIR):
        return {"windows": []}

    files = [
        f for f in os.listdir(RESULTS_DIR)
        if f.endswith(".json")
    ]

    files = sorted(files, key=lambda x: int(x.split("_")[1].split(".")[0]))

    for file in files:
        if file.endswith(".json"):
            path = os.path.join(RESULTS_DIR, file)

            with open(path, "r") as f:
                content = json.load(f)

                data.append({
                    "window_id": content.get("window_id"),
                    "trust_state": content.get("trust_state"),
                    "anomaly_ratio": content.get("anomaly_ratio"),
                    "explanation": content.get("explanation", [])
                })

    return {"windows": data}


@router.get("/coverage")
def get_coverage():

    if not os.path.exists(COVERAGE_FILE):
        return {"coverage": {}}

    with open(COVERAGE_FILE, "r") as f:
        data = json.load(f)

    return data