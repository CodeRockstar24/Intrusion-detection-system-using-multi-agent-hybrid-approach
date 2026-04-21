import pandas as pd
import numpy as np

DATA_PATH = r"C:\Users\elroy\OneDrive\Desktop\Cybersecurity Project CECS378\data\MachineLearningCVE\cleaned_data.csv"
OUTPUT_FILE = "network_demo_data.csv"

real_df = pd.read_csv(DATA_PATH)

def generate_dataset(n=3000):

    df = real_df.sample(n=n, replace=True, random_state=42).copy()

    # convert numeric columns to float
    numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
    df[numeric_cols] = df[numeric_cols].astype(float)

    # assign labels
    labels = ["Benign", "DDoS", "DoS", "PortScan"]
    df["Label"] = np.random.choice(labels, size=n)

    # masks
    ddos = df["Label"] == "DDoS"
    dos = df["Label"] == "DoS"
    port = df["Label"] == "PortScan"

    # DDoS
    if "Flow Packets/s" in df.columns:
        df.loc[ddos, "Flow Packets/s"] *= np.random.uniform(3, 8, ddos.sum())

    if "Flow Bytes/s" in df.columns:
        df.loc[ddos, "Flow Bytes/s"] *= np.random.uniform(3, 8, ddos.sum())

    if "SYN Flag Count" in df.columns:
        df.loc[ddos, "SYN Flag Count"] *= np.random.uniform(3, 6, ddos.sum())

    # DoS
    if "Flow Packets/s" in df.columns:
        df.loc[dos, "Flow Packets/s"] *= np.random.uniform(2, 5, dos.sum())

    if "Flow Bytes/s" in df.columns:
        df.loc[dos, "Flow Bytes/s"] *= np.random.uniform(2, 5, dos.sum())

    # PortScan
    if "Total Fwd Packets" in df.columns:
        df.loc[port, "Total Fwd Packets"] *= np.random.uniform(2, 5, port.sum())

    if "Total Backward Packets" in df.columns:
        df.loc[port, "Total Backward Packets"] *= np.random.uniform(0.1, 0.5, port.sum())

    if "SYN Flag Count" in df.columns:
        df.loc[port, "SYN Flag Count"] *= np.random.uniform(2, 4, port.sum())

    # SAFE CLIP ONLY NUMERIC
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    df[numeric_cols] = df[numeric_cols].clip(lower=0)

    return df


if __name__ == "__main__":

    df = generate_dataset(3000)

    df.to_csv(OUTPUT_FILE, index=False)

    print("✅ Dataset generated successfully")
    print(df["Label"].value_counts())