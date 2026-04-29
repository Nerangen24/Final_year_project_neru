# policy/rules.py

DEFAULT_RULES = {
    "HIGH_TRUST": {
        "ingress": [
            {"protocol": "TCP", "ports": "any", "action": "ALLOW"},
            {"protocol": "UDP", "ports": "any", "action": "ALLOW"},
        ],
        "egress": [
            {"protocol": "ANY", "ports": "any", "action": "ALLOW"},
        ],
    },

    "MEDIUM_TRUST": {
        "ingress": [
            {"protocol": "TCP", "ports": [80, 443], "action": "ALLOW"},
            {"protocol": "TCP", "ports": "other", "action": "RATE_LIMIT"},
            {"protocol": "UDP", "ports": "any", "action": "RATE_LIMIT"},
        ],
        "egress": [
            {"protocol": "ANY", "ports": "any", "action": "ALLOW"},
        ],
    },

    "LOW_TRUST": {
        "ingress": [
            {"protocol": "TCP", "ports": [443], "action": "ALLOW"},
            {"protocol": "ANY", "ports": "any", "action": "DROP"},
        ],
        "egress": [
            {"protocol": "ANY", "ports": "any", "action": "BLOCK"},
        ],
    },
}
