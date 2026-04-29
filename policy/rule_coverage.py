import json
import os
from collections import defaultdict

OUTPUT_FILE = "results/rule_coverage.json"

rule_hits = defaultdict(int)
trust_hits = defaultdict(int)
feature_hits = defaultdict(int)


def update_rule_coverage(trust_state, policy, feature_explanation=None):
    trust_hits[trust_state] += 1

    if policy["rate_limit"] != "NONE":
        rule_hits[f"RATE_LIMIT_{policy['rate_limit']}"] += 1

    if policy["ingress"] != "ALLOW":
        rule_hits["INGRESS_RESTRICT"] += 1

    if policy["egress"] != "ALLOW":
        rule_hits["EGRESS_BLOCK"] += 1

    if policy["quarantine"]:
        rule_hits["QUARANTINE"] += 1

    if feature_explanation:
        for f in feature_explanation:
            feature_hits[f] += 1

    flush_coverage()


def flush_coverage():
    os.makedirs("results", exist_ok=True)

    data = {
        "rules": dict(rule_hits),
        "trust_states": dict(trust_hits),
        "feature_triggers": dict(feature_hits)
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)