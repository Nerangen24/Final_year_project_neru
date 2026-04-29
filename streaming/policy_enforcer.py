def enforce_policy(trust_state, window_id):
    """
    Simulated Zero Trust policy enforcement
    """

    if trust_state == "HIGH_TRUST":
        action = "ALLOW"
    elif trust_state == "MEDIUM_TRUST":
        action = "MONITOR"
    else:
        action = "ISOLATE"

    print(
        f"Window {window_id:03d} | "
        f"Trust={trust_state} → Enforcement={action}"
    )

    return action
