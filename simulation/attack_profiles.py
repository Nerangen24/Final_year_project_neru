import pandas as pd
import numpy as np

def build_attack_dataset(input_csv, output_csv):

    df = pd.read_csv(input_csv)

    attack_start = int(len(df) * 0.6)
    attack_end = attack_start + int(len(df) * 0.15)

    df.loc[attack_start:attack_end, "src_bytes"] *= 15
    df.loc[attack_start:attack_end, "dst_bytes"] *= 20
    df.loc[attack_start:attack_end, "src_pkts"] *= 10
    df.loc[attack_start:attack_end, "dst_pkts"] *= 10

    df.to_csv(output_csv, index=False)
    print("✔ Attack scenarios written to", output_csv)
