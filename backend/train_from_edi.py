"""
train_from_edi.py
=================
Trains the backend ML/DL detection models using the real CICIDS2017 parquet
dataset from C:\\Users\\sujit\\Downloads\\EDI_SY\\EDI_Dataset.

Pipeline:
  1. Load all .parquet files (8 attack-type files + benign)
  2. Clean: drop inf/NaN, winsorise outliers
  3. Map multi-class labels  (BENIGN=0, PortScan=1, DoS/DDoS=2, Brute=3, Other=4)
  4. Map CICIDS2017 raw columns  ->  backend FEATURE_COLUMNS (25 features)
  5. Train:  IsolationForest + Autoencoder  (anomaly detectors)
             RandomForest   + LSTM          (classifiers)
  6. Save all model files to  backend/models/

Run from the backend directory:
    python train_from_edi.py
"""

import os, sys, glob, warnings, time
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Ensure imports from this backend folder work ────────────────────────────
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
EDI_DATASET = r"C:\Users\sujit\Downloads\EDI_SY\EDI_Dataset"

sys.path.insert(0, BACKEND_DIR)

# ── Import existing engine (loads feature columns, model classes, etc.) ─────
from ml_engine import MLEngine, FEATURE_COLUMNS, ATTACK_LABELS, MODEL_DIR

# ── Label mapping: CICIDS2017 label strings → class index ───────────────────
LABEL_MAP = {
    # Normal / Benign
    "BENIGN": 0, "Benign": 0, "benign": 0,

    # Port Scan
    "PortScan": 1, "Port Scan": 1,

    # DoS / DDoS
    "DoS Hulk": 2, "DoS GoldenEye": 2, "DoS slowloris": 2,
    "DoS Slowhttptest": 2, "DDoS": 2, "DoS": 2, "Heartbleed": 2,

    # Brute Force
    "FTP-Patator": 3, "SSH-Patator": 3, "Brute Force": 3,
    "Web Attack \u00e2\u20ac\u201c Brute Force": 3,
    "Web Attack ? Brute Force": 3,
    "Web Attack – Brute Force": 3,

    # Other / Suspicious  (infiltration, botnet, web-sql, web-xss, …)
    "Infiltration": 4, "Bot": 4, "Botnet": 4,
    "Web Attack \u00e2\u20ac\u201c XSS": 4, "Web Attack \u00e2\u20ac\u201c Sql Injection": 4,
    "Web Attack – XSS": 4, "Web Attack – Sql Injection": 4,
    "Web Attack ? XSS": 4, "Web Attack ? Sql Injection": 4,
}


def load_parquets(data_dir: str, max_rows_per_file: int = 40_000) -> pd.DataFrame:
    """Load all .parquet files and sample to keep memory manageable."""
    files = sorted(glob.glob(os.path.join(data_dir, "*.parquet")))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {data_dir}")

    print(f"\n[Loader] Found {len(files)} parquet file(s) in {data_dir}")
    dfs = []
    for f in files:
        df = pd.read_parquet(f)
        if len(df) > max_rows_per_file:
            df = df.sample(n=max_rows_per_file, random_state=42)
        print(f"  Loaded {os.path.basename(f):50s} -> {len(df):>7,} rows")
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[Loader] Combined: {len(combined):,} rows, {combined.shape[1]} columns")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/NaN, winsorise at [1 %, 99 %] and strip column whitespace."""
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    # Winsorise numeric features only
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for col in num_cols:
        p01, p99 = df[col].quantile([0.01, 0.99])
        df[col] = df[col].clip(lower=p01, upper=p99)

    print(f"[Clean]  After cleaning: {len(df):,} rows")
    return df


def map_labels(df: pd.DataFrame) -> np.ndarray:
    """Return integer class array from the Label column."""
    label_col = "Label" if "Label" in df.columns else "label"
    if label_col not in df.columns:
        raise KeyError("No 'Label' column found in dataset.")

    # Sanitise unicode weirdness in labels
    df[label_col] = (
        df[label_col]
        .astype(str)
        .str.strip()
        .str.encode("ascii", errors="replace")
        .str.decode("ascii")
    )
    y = df[label_col].map(lambda x: LABEL_MAP.get(x, 4)).values
    counts = {ATTACK_LABELS[k]: int((y == k).sum()) for k in ATTACK_LABELS}
    print(f"[Labels] Distribution: {counts}")
    return y


def map_cicids_to_features(df: pd.DataFrame) -> np.ndarray:
    """
    Map the 78 raw CICIDS2017 / CICFlowMeter columns to our 25 FEATURE_COLUMNS.
    Any column not present in the parquet is filled with 0.
    """

    def get(col, default=0.0):
        return df[col] if col in df.columns else pd.Series(default, index=df.index)

    total_fwd  = get("Total Fwd Packets").clip(lower=0)
    total_bwd  = get("Total Backward Packets").clip(lower=0)
    total_pkts = (total_fwd + total_bwd).clip(lower=1)

    fwd_len = get("Fwd Packets Length Total")
    bwd_len = get("Bwd Packets Length Total")

    flow_pps = get("Flow Packets/s").clip(lower=0)
    flow_bps = get("Flow Bytes/s").clip(lower=0)

    syn_count = get("SYN Flag Count").clip(lower=0)
    rst_count = get("RST Flag Count").clip(lower=0)

    X_dict = {
        "flow_duration":             get("Flow Duration").clip(lower=0) / 1_000_000.0,
        "packet_count":              total_pkts,
        "byte_count":                (fwd_len + bwd_len).clip(lower=0),
        "packets_per_second":        flow_pps,
        "bytes_per_second":          flow_bps,
        "avg_packet_size":           get("Avg Packet Size").clip(lower=0),
        "connection_rate":           flow_pps,
        "syn_packet_ratio":          (syn_count / total_pkts).clip(0, 1),
        "unique_ports_contacted":    np.ones(len(df)),          # not directly available
        "failed_connection_attempts": rst_count,
        "burst_rate":                flow_pps,
        "syn_count":                 syn_count,
        "rst_count":                 rst_count,
        "unique_targets":            np.ones(len(df)),          # not directly available
        "fwd_packet_count":          total_fwd,
        "bwd_packet_count":          total_bwd,
        "fwd_byte_count":            fwd_len.clip(lower=0),
        "bwd_byte_count":            bwd_len.clip(lower=0),
        "iat_mean":                  get("Flow IAT Mean").clip(lower=0) / 1_000_000.0,
        "iat_std":                   get("Flow IAT Std").clip(lower=0)  / 1_000_000.0,
        "iat_max":                   get("Flow IAT Max").clip(lower=0)  / 1_000_000.0,
        "iat_min":                   get("Flow IAT Min").clip(lower=0)  / 1_000_000.0,
        "is_lateral":                np.zeros(len(df)),
        "is_outbound":               np.zeros(len(df)),
        "is_inbound":                np.ones(len(df)),
    }

    # Build matrix in the exact order FEATURE_COLUMNS expects
    X = np.column_stack([np.asarray(X_dict[col], dtype=np.float64) for col in FEATURE_COLUMNS])
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    print(f"[Map]    Feature matrix: {X.shape}")
    return X


def main():
    t0 = time.time()
    print("=" * 60)
    print("  Training Backend Models on EDI_SY / CICIDS2017 Dataset")
    print("=" * 60)

    # 1. Load
    df = load_parquets(EDI_DATASET, max_rows_per_file=35_000)

    # 2. Clean
    df = clean(df)

    # 3. Labels
    y = map_labels(df)

    # 4. Map to 25 FEATURE_COLUMNS
    X = map_cicids_to_features(df)

    # 5. Train via the engine's internal method
    print("\n[Train] Initialising MLEngine and training all models...")
    engine = MLEngine.__new__(MLEngine)          # skip __init__ / auto-train
    engine.ip_sequence_buffer = {}
    engine.sequence_length = 5
    engine.is_trained = False
    engine.scaler = None
    engine.anomaly_detector = None
    engine.classifier = None
    engine.autoencoder = None
    engine.lstm = None
    os.makedirs(MODEL_DIR, exist_ok=True)

    engine._train_from_data(X, y)

    # 6. Report
    elapsed = time.time() - t0
    acc = getattr(engine, "last_accuracy", None)
    print(f"\n{'=' * 60}")
    print(f"  Training complete in {elapsed:.1f}s")
    print(f"  Classifier training accuracy: {acc:.4f}" if acc else "")
    print(f"  Models saved to: {MODEL_DIR}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
