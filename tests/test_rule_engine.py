from policy.rule_engine import evaluate_rules

def test_packet_flood():
    explanation = {
        "src_pkts": 9.5,
        "dst_pkts": 1.2,
        "src_bytes": 0.4,
        "dst_bytes": 0.3
    }

    policy = evaluate_rules(
        trust_state="LOW_TRUST",
        feature_explanation=explanation
    )

    assert "RATE_LIMIT" in policy
    assert "BLOCK_EGRESS" not in policy


def test_data_exfiltration():
    explanation = {
        "dst_bytes": 11.2,
        "src_bytes": 0.5,
        "src_pkts": 1.0,
        "dst_pkts": 1.1
    }

    policy = evaluate_rules(
        trust_state="LOW_TRUST",
        feature_explanation=explanation
    )

    assert "BLOCK_EGRESS" in policy
