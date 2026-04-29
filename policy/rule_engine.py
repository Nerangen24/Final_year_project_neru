def evaluate_rules(trust_state, feature_explanation=None):

    if trust_state == "LOW_TRUST":
        return {
            "ingress": "RESTRICT",
            "egress": "BLOCK",
            "rate_limit": "SEVERE",
            "logging": "FORENSIC",
            "quarantine": True
        }

    elif trust_state == "MEDIUM_TRUST":
        return {
            "ingress": "ALLOW",
            "egress": "ALLOW",
            "rate_limit": "MODERATE",
            "logging": "DETAILED",
            "quarantine": False
        }

    else:
        return {
            "ingress": "ALLOW",
            "egress": "ALLOW",
            "rate_limit": "NONE",
            "logging": "BASIC",
            "quarantine": False
        }