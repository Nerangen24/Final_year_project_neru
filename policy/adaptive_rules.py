# policy/adaptive_rules.py

def adapt_rules(trust_state, feature_explanation):
    rules = {
        "ingress": [],
        "egress": []
    }

    if trust_state == "HIGH_TRUST":
        rules["ingress"].append({"protocol": "ANY", "ports": "any", "action": "ALLOW"})
        rules["egress"].append({"protocol": "ANY", "ports": "any", "action": "ALLOW"})
        return rules

    # If packet-based flood detected
    if "src_pkts" in feature_explanation or "dst_pkts" in feature_explanation:
        rules["ingress"].append({"protocol": "UDP", "ports": "any", "action": "RATE_LIMIT"})
        rules["ingress"].append({"protocol": "ICMP", "ports": "any", "action": "DROP"})

    # If byte-level exfiltration detected
    if "dst_bytes" in feature_explanation:
        rules["egress"].append({"protocol": "ANY", "ports": "any", "action": "RATE_LIMIT"})

    if trust_state == "LOW_TRUST":
        rules["ingress"].append({"protocol": "ANY", "ports": "any", "action": "DROP"})
        rules["egress"].append({"protocol": "ANY", "ports": "any", "action": "BLOCK"})

    return rules
