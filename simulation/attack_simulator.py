import pandas as pd

INPUT = "../outputs/sampled_data.csv"
OUTPUT = "../outputs/attack_data.csv"

df = pd.read_csv(INPUT)

attack_start = int(len(df) * 0.6)
attack_end = attack_start + int(len(df) * 0.1)

df.loc[attack_start:attack_end, "src_bytes"] *= 20
df.loc[attack_start:attack_end, "dst_bytes"] *= 20
df.loc[attack_start:attack_end, "src_pkts"] *= 10
df.loc[attack_start:attack_end, "dst_pkts"] *= 10

df.to_csv(OUTPUT, index=False)

print("✔ Attack traffic injected successfully")
