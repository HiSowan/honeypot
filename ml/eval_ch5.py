"""Chapter 5 evaluation — run from ~/honeypot with venv active.

    python ml/eval_ch5.py

Outputs results to ml/evaluation_results.txt and prints to stdout.
No relative imports — works as a plain script.
"""
import sys, warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# Allow running from any cwd
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from collections import Counter

MODELS   = ROOT / "ml" / "models"
UNSW_CSV = ROOT / "data" / "raw" / "UNSW_NB15_training-set.CSV"
LIVE_LOG = Path("/opt/zeek/logs/current/conn.log")
OUT      = ROOT / "ml" / "evaluation_results.txt"

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]
ATTACK_CATS = [
    "Normal", "Fuzzers", "Analysis", "Backdoors", "DoS",
    "Exploits", "Generic", "Reconnaissance", "Shellcode", "Worms",
]

lines = []

def out(s=""):
    print(s)
    lines.append(str(s))

def sec(title):
    bar = "=" * 65
    out(); out(bar); out(title); out(bar)


# ── 1. RF per-class report on UNSW-NB15 ──────────────────────────────────
sec("1. RANDOM FOREST — Per-Class Report (UNSW-NB15 test set)")

df = pd.read_csv(UNSW_CSV, low_memory=False)
df.columns = df.columns.str.strip().str.lower()
df = df.rename(columns={
    "dur": "duration", "sbytes": "orig_bytes", "dbytes": "resp_bytes",
    "spkts": "orig_pkts", "dpkts": "resp_pkts",
    "proto": "proto", "state": "conn_state",
})
for p in ("tcp", "udp", "icmp"):
    df[f"proto_{p}"] = (df["proto"].str.lower() == p).astype(int)
for s in ("S0", "SF", "REJ", "RSTO"):
    df[f"conn_state_{s}"] = (df["conn_state"].str.upper() == s).astype(int)

X = df[FEATURE_COLS].fillna(0).astype(float)
y = df["attack_cat"].fillna("Normal").str.strip()
y = y.where(y.isin(ATTACK_CATS), other="Normal")

_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

rf = joblib.load(MODELS / "rf_attack_type.joblib")
y_pred = rf.predict(X_test)

out(f"Train size : {len(X) - len(X_test)}")
out(f"Test size  : {len(X_test)}")
out(f"Classes    : {list(rf.classes_)}")
out()
out(classification_report(y_test, y_pred, zero_division=0))


# ── 2. Parse live Zeek conn.log ───────────────────────────────────────────
sec("2. LIVE ZEEK DATA — Feature Matrix")

rows = []
with open(LIVE_LOG) as f:
    for line in f:
        if line.startswith("#"):
            continue
        p = line.strip().split("\t")
        if len(p) < 20:
            continue
        try:
            proto = p[6].lower()
            state = p[11].upper()
            row = {
                "duration":       float(p[8])  if p[8]  not in ("-", "") else 0.0,
                "orig_bytes":     float(p[9])  if p[9]  not in ("-", "") else 0.0,
                "resp_bytes":     float(p[10]) if p[10] not in ("-", "") else 0.0,
                "orig_pkts":      float(p[16]) if p[16] not in ("-", "") else 0.0,
                "resp_pkts":      float(p[18]) if p[18] not in ("-", "") else 0.0,
                "proto_tcp":      int(proto == "tcp"),
                "proto_udp":      int(proto == "udp"),
                "proto_icmp":     int(proto == "icmp"),
                "conn_state_S0":  int(state == "S0"),
                "conn_state_SF":  int(state == "SF"),
                "conn_state_REJ": int(state == "REJ"),
                "conn_state_RSTO":int(state == "RSTO"),
            }
            rows.append(row)
        except Exception:
            continue

X_live = pd.DataFrame(rows, columns=FEATURE_COLS)
out(f"Records parsed: {len(X_live)}")


# ── 3 & 4. IForest comparison ─────────────────────────────────────────────
def iforest_stats(path, label, X):
    sec(f"IForest — {label}")
    model  = joblib.load(path)
    scores = model.decision_function(X)
    preds  = model.predict(X)
    n      = int((preds == -1).sum())
    out(f"Model     : {label}")
    out(f"Anomalies : {n} / {len(X)}  ({100*n/len(X):.1f}%)")
    out(f"Score mean: {scores.mean():.4f}   std: {scores.std():.4f}")
    out(f"Score min : {scores.min():.4f}   max: {scores.max():.4f}   median: {float(np.median(scores)):.4f}")
    out(f"Below -0.1: {int((scores < -0.1).sum())}   "
        f"Below -0.2: {int((scores < -0.2).sum())}   "
        f"Below -0.3: {int((scores < -0.3).sum())}")

iforest_stats(MODELS / "iforest_anomaly.joblib", "UNSW-NB15 baseline", X_live)
iforest_stats(MODELS / "iforest_live.joblib",    "Live-retrained",     X_live)


# ── 5. RF attack type distribution on live data ───────────────────────────
sec("5. RF — Attack Type Distribution on Live Data")
live_preds = rf.predict(X_live)
cnt = Counter(live_preds)
out(f"{'Attack type':<22} {'Count':>6}   {'%':>6}")
out("-" * 38)
for cat in ATTACK_CATS:
    n = cnt.get(cat, 0)
    out(f"{cat:<22} {n:>6}   {100*n/len(live_preds):>5.1f}%")


# ── Save ──────────────────────────────────────────────────────────────────
OUT.write_text("\n".join(lines), encoding="utf-8")
sec(f"DONE — saved to {OUT}")
