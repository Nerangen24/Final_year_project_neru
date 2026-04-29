# Defines network-level rules (router / firewall semantics)

RULES = {
    "HIGH_TRUST": {
        "ingress": "ALLOW",
        "egress": "ALLOW",
        "rate_limit": None,
        "logging": "BASIC",
        "quarantine": False
    },

    "MEDIUM_TRUST": {
        "ingress": "ALLOW",
        "egress": "ALLOW",
        "rate_limit": "MODERATE",
        "logging": "DETAILED",
        "quarantine": False
    },

    "LOW_TRUST": {
        "ingress": "RESTRICT",
        "egress": "DENY",
        "rate_limit": "SEVERE",
        "logging": "FORENSIC",
        "quarantine": True
    }
}
