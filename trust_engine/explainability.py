def generate_explanation(window_df, anomaly_ratio, mean, std):
    reasons = []

    if anomaly_ratio > mean + 2 * std:
        reasons.append("Anomaly score significantly above normal baseline")
    elif anomaly_ratio > mean + std:
        reasons.append("Anomaly score moderately above normal baseline")

    if window_df["src_bytes"].mean() > 50000:
        reasons.append("High source data volume")

    if window_df["dst_bytes"].mean() > 50000:
        reasons.append("High destination data volume")

    if window_df["src_pkts"].mean() > 1000:
        reasons.append("High source packet rate")

    if window_df["dst_pkts"].mean() > 1000:
        reasons.append("High destination packet rate")

    if window_df["missed_bytes"].mean() > 0:
        reasons.append("Packet loss or missed bytes detected")

    if not reasons:
        reasons.append("Traffic behavior within normal baseline")

    return reasons