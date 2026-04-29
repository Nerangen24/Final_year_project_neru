def analyze_features(window_df, baseline_df, top_k=3):

    diff = (window_df.mean() - baseline_df.mean()).abs()
    diff = diff.sort_values(ascending=False)

    return list(diff.head(top_k).index)
