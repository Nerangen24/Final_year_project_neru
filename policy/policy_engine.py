from policy.rule_set import RULES

def get_policy(trust_state: str) -> dict:
    """
    Maps trust state to network policy rules.
    """
    return RULES.get(trust_state, RULES["LOW_TRUST"])
