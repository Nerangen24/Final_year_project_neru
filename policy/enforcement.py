from policy.rate_limiter import check_rate_limit

def enforce_policy(window_id, trust_state, policy, source_id):

    source_id = "simulated_source" 

    allowed = check_rate_limit(source_id, trust_state)

    print(f"Window {window_id:03d} | Trust={trust_state}")

    if not allowed:
        print(" ❌ BLOCKED by rate limiter")
        return

    if policy.get("rate_limit") == "MODERATE":
        print(" → Rate limiting applied: MODERATE")

    elif policy.get("rate_limit") == "SEVERE":
        print(" → Rate limiting applied: SEVERE")

    print(f" → Logging level: {policy.get('logging')}")