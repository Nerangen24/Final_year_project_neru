def decide_trust(anomaly_ratio, mean, std):
    if anomaly_ratio > mean + 0.8 * std:
        return "LOW_TRUST"
    elif anomaly_ratio > mean + 0.3 * std:
        return "MEDIUM_TRUST"
    else:
        return "HIGH_TRUST"