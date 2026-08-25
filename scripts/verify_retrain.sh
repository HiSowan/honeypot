#!/usr/bin/env bash
# Parts 1, 2, 4, 5 verification script.
# Run from ~/honeypot with venv active:
#
#   cd ~/honeypot
#   git pull
#   source venv/bin/activate
#   bash scripts/verify_retrain.sh 2>&1 | tee /tmp/verify_output.txt
#
# Then: cat /tmp/verify_output.txt   (paste full output to Claude)

set -euo pipefail
SEP="========================================"

CSV="data/raw/UNSW_NB15_training-set.CSV"
MODELS="ml/models"
SHADOW="/var/log/honeypot/shadow_mode.csv"
LIVE_LOG="/opt/zeek/logs/current/conn.log"
ZEEK_ARCHIVE_DIR="/opt/zeek/logs"

# ── Part 1a: Model freshness ───────────────────────────────────────────────────
echo "$SEP"
echo "PART 1a: MODEL FRESHNESS — mtime and SHA-256"
echo "$SEP"
ls -la "$MODELS"/*.joblib 2>/dev/null || echo "No .joblib files found in $MODELS"
echo ""
echo "SHA-256:"
sha256sum "$MODELS"/*.joblib 2>/dev/null || echo "sha256sum failed"
echo ""

# ── Part 1b: Confirm eval_ch5 model paths ─────────────────────────────────────
echo "$SEP"
echo "PART 1b: MODEL PATHS USED BY eval_ch5.py (runtime confirmation)"
echo "$SEP"
python3 - <<'PYEOF'
from pathlib import Path
ROOT = Path(".")
MODELS = ROOT / "ml" / "models"
paths = {
    "rf_attack_type.joblib":  MODELS / "rf_attack_type.joblib",
    "iforest_anomaly.joblib": MODELS / "iforest_anomaly.joblib",
    "iforest_live.joblib":    MODELS / "iforest_live.joblib",
}
print("eval_ch5.py loads these paths (from code):")
for name, p in paths.items():
    import os, hashlib
    if p.exists():
        st = os.stat(p)
        h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
        print(f"  {name}: exists, mtime={st.st_mtime:.0f}, sha256_prefix={h}")
    else:
        print(f"  {name}: NOT FOUND")
PYEOF
echo ""

# ── Part 1c: Feature importances (new model; old overwritten) ─────────────────
echo "$SEP"
echo "PART 1c: RF FEATURE IMPORTANCES (retrained model)"
echo "$SEP"
python3 - <<'PYEOF'
import joblib
from pathlib import Path
import numpy as np

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

rf = joblib.load("ml/models/rf_attack_type.joblib")
importances = rf.feature_importances_
ranked = sorted(zip(FEATURE_COLS, importances), key=lambda x: -x[1])
print("Feature importance ranking (retrained model, corrected encoding):")
for rank, (feat, imp) in enumerate(ranked, 1):
    tag = " ← was dead (all-zero) before fix" if "conn_state" in feat else ""
    print(f"  {rank:2}. {feat:<22} {imp:.5f}{tag}")

print()
cs_total = sum(imp for feat, imp in ranked if "conn_state" in feat)
print(f"Total conn_state importance: {cs_total:.5f}")
print(f"Conclusion: conn_state features {'ARE' if cs_total > 0 else 'ARE NOT'} contributing to the model")
PYEOF
echo ""

# ── Part 1c note: old model gone ──────────────────────────────────────────────
echo "NOTE: The old (pre-fix) model was overwritten by the retrain."
echo "Direct before/after per-record agreement cannot be computed."
echo "Evidence that the model changed: conn_state feature importances above (see PART 1c)."
echo ""

# ── Part 1d: Inference-time feature distribution ──────────────────────────────
echo "$SEP"
echo "PART 1d: FEATURE DISTRIBUTION AT INFERENCE TIME (live Zeek records)"
echo "$SEP"
python3 - <<'PYEOF'
import sys
from pathlib import Path

LIVE_LOG = Path("/opt/zeek/logs/current/conn.log")
FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

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
                "duration":        float(p[8])  if p[8]  not in ("-","") else 0.0,
                "orig_bytes":      float(p[9])  if p[9]  not in ("-","") else 0.0,
                "resp_bytes":      float(p[10]) if p[10] not in ("-","") else 0.0,
                "orig_pkts":       float(p[16]) if p[16] not in ("-","") else 0.0,
                "resp_pkts":       float(p[18]) if p[18] not in ("-","") else 0.0,
                "proto_tcp":       int(proto == "tcp"),
                "proto_udp":       int(proto == "udp"),
                "proto_icmp":      int(proto == "icmp"),
                "conn_state_S0":   int(state == "S0"),
                "conn_state_SF":   int(state == "SF"),
                "conn_state_REJ":  int(state == "REJ"),
                "conn_state_RSTO": int(state == "RSTO"),
                "_state_raw":      state,
            }
            rows.append(row)
        except Exception:
            continue

import pandas as pd
df = pd.DataFrame(rows)
n = len(df)
print(f"Live records parsed: {n}")
print()
print("Raw Zeek conn_state value_counts (live records):")
print(df["_state_raw"].value_counts().head(15).to_string())
print()
print("conn_state one-hot columns (sum and % of records):")
for col in ["conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO"]:
    s = df[col].sum()
    print(f"  {col:<22}: {s:>5}  ({100*s/n:.1f}%)")
PYEOF
echo ""

# ── Part 2: State coverage analysis ───────────────────────────────────────────
echo "$SEP"
echo "PART 2: STATE COVERAGE — UNSW vs Live Zeek overlap"
echo "$SEP"
python3 - <<'PYEOF'
import pandas as pd
from pathlib import Path
import sys

CSV = Path("data/raw/UNSW_NB15_training-set.CSV")
LIVE = Path("/opt/zeek/logs/current/conn.log")

# ── UNSW-NB15 ──
df = pd.read_csv(CSV, low_memory=False)
df.columns = df.columns.str.strip().str.lower()
from ml.features import UNSW_COL_MAP
df = df.rename(columns=UNSW_COL_MAP)

print(f"UNSW-NB15 total records: {len(df):,}")
print()
print("Raw Argus state distribution:")
vc = df["conn_state"].str.upper().value_counts()
for state, cnt in vc.items():
    print(f"  {state:<10} {cnt:>8,}  ({100*cnt/len(df):.2f}%)")

MAP = {"REQ": "S0", "FIN": "SF", "CON": "SF", "CLO": "SF", "RST": "RSTO",
       "S0": "S0", "SF": "SF", "REJ": "REJ", "RSTO": "RSTO", "OTH": "OTH"}
mapped = df["conn_state"].str.upper().map(MAP).fillna("")
print()
print("After Argus→Zeek mapping (conn_state_ columns):")
for state in ("S0", "SF", "REJ", "RSTO", ""):
    cnt = (mapped == state).sum()
    label = state if state else "(unmapped/INT/ECO/etc)"
    print(f"  {label:<12} {cnt:>8,}  ({100*cnt/len(df):.2f}%)")

# ── Live Zeek ──
live_states = []
with open(LIVE) as f:
    for line in f:
        if line.startswith("#"):
            continue
        p = line.strip().split("\t")
        if len(p) >= 12:
            live_states.append(p[11].upper())

from collections import Counter
live_vc = Counter(live_states)
total_live = len(live_states)
print()
print(f"Live Zeek total records: {total_live:,}")
print("Live Zeek conn_state distribution:")
for state, cnt in sorted(live_vc.items(), key=lambda x: -x[1]):
    print(f"  {state:<12} {cnt:>5,}  ({100*cnt/total_live:.1f}%)")

# ── Overlap ──
unsw_after_map = set(s for s in mapped.unique() if s)
live_set = set(live_vc.keys())
print()
print("States in UNSW training data (after mapping):", sorted(unsw_after_map))
print("States in live Zeek data:", sorted(live_set))
overlap = unsw_after_map & live_set
missing = live_set - unsw_after_map
print("Overlap:", sorted(overlap))
print("Live states NOT in UNSW training:", sorted(missing))

# Fraction of live records whose state is covered by training
covered = sum(live_vc[s] for s in overlap if s in live_vc)
print()
print(f"Live records with state covered by training: {covered}/{total_live} ({100*covered/total_live:.1f}%)")
print(f"Live records with state NOT in training:     {total_live-covered}/{total_live} ({100*(total_live-covered)/total_live:.1f}%)")

# Specific REQ/S0 analysis
req_count = (df["conn_state"].str.upper() == "REQ").sum()
s0_live = live_vc.get("S0", 0)
print()
print(f"UNSW REQ records (→ S0): {req_count:,}  ({100*req_count/len(df):.2f}% of training data)")
print(f"Live S0 records:          {s0_live:,}  ({100*s0_live/total_live:.1f}% of live data)")
PYEOF
echo ""

# ── Part 4a: Locate 432-record session in Zeek archives ───────────────────────
echo "$SEP"
echo "PART 4a: LOCATE 432-RECORD SESSION (looking for 2026-08-06 archive)"
echo "$SEP"
python3 - <<'PYEOF'
import subprocess, os
from pathlib import Path

# Look for Zeek archived logs from 2026-08-06 (original evaluation date)
zeek_log_dir = Path("/opt/zeek/logs")
candidates = []
for p in sorted(zeek_log_dir.rglob("conn*.log*")):
    # Check if it's from 2026-08-06
    if "2026-08-06" in str(p) or "20260806" in str(p):
        candidates.append(p)

if candidates:
    print("Found archived conn logs from 2026-08-06:")
    for p in candidates:
        size = os.stat(p).st_size
        print(f"  {p}  ({size} bytes)")
else:
    print("No Zeek archived conn logs found for 2026-08-06")
    # List available dates
    print("\nAvailable Zeek log dates (all subdirs):")
    for p in sorted(zeek_log_dir.iterdir()):
        if p.is_dir() and p.name != "current":
            conn_logs = list(p.glob("conn*"))
            if conn_logs:
                print(f"  {p.name}: {len(conn_logs)} conn log(s)")
PYEOF
echo ""

# ── Part 4b: IForest live model training set boundary ─────────────────────────
echo "$SEP"
echo "PART 4b: IFOREST_LIVE TRAINING BOUNDARY AND HELD-OUT SET"
echo "$SEP"
python3 - <<'PYEOF'
import os, joblib
from pathlib import Path

LIVE_PATH = Path("ml/models/iforest_live.joblib")
LIVE_LOG  = Path("/opt/zeek/logs/current/conn.log")

# mtime of live IForest model = when training completed
if not LIVE_PATH.exists():
    print("iforest_live.joblib not found")
    raise SystemExit(1)

model_mtime = os.stat(LIVE_PATH).st_mtime
from datetime import datetime, timezone
model_dt = datetime.fromtimestamp(model_mtime, tz=timezone.utc)
print(f"iforest_live.joblib mtime: {model_dt.isoformat()}")
print(f"  (unix timestamp: {model_mtime:.0f})")

# Parse live conn.log, split on model mtime
rows_train_window = []  # records that existed when model was trained (approx)
rows_held_out = []      # records added after model was trained

with open(LIVE_LOG) as f:
    for line in f:
        if line.startswith("#"):
            continue
        p = line.strip().split("\t")
        if len(p) < 20:
            continue
        try:
            ts = float(p[0])
            proto = p[6].lower()
            state = p[11].upper()
            row = {
                "ts": ts,
                "src_ip": p[2],
                "duration":        float(p[8])  if p[8]  not in ("-","") else 0.0,
                "orig_bytes":      float(p[9])  if p[9]  not in ("-","") else 0.0,
                "resp_bytes":      float(p[10]) if p[10] not in ("-","") else 0.0,
                "orig_pkts":       float(p[16]) if p[16] not in ("-","") else 0.0,
                "resp_pkts":       float(p[18]) if p[18] not in ("-","") else 0.0,
                "proto_tcp":       int(proto == "tcp"),
                "proto_udp":       int(proto == "udp"),
                "proto_icmp":      int(proto == "icmp"),
                "conn_state_S0":   int(state == "S0"),
                "conn_state_SF":   int(state == "SF"),
                "conn_state_REJ":  int(state == "REJ"),
                "conn_state_RSTO": int(state == "RSTO"),
            }
            if ts < model_mtime:
                rows_train_window.append(row)
            else:
                rows_held_out.append(row)
        except Exception:
            continue

print(f"Records with timestamp < model_mtime (train window): {len(rows_train_window)}")
print(f"Records with timestamp >= model_mtime (held-out):    {len(rows_held_out)}")
print(f"Total: {len(rows_train_window) + len(rows_held_out)}")

# Note: the live IForest was trained on 345 Kali records from the train_window set
train_kali = [r for r in rows_train_window if r["src_ip"] == "10.10.0.2"]
print(f"\nKali records (10.10.0.2) in train window: {len(train_kali)}")
print("(iforest_live was trained on 345 of these — using the 345 most recent Kali records)")

PYEOF
echo ""

# ── Part 4c: Apples-to-apples IForest comparison ─────────────────────────────
echo "$SEP"
echo "PART 4c: IFOREST COMPARISON (same population for both models)"
echo "$SEP"
python3 - <<'PYEOF'
import joblib, os
import numpy as np
import pandas as pd
from pathlib import Path

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

LIVE_LOG = Path("/opt/zeek/logs/current/conn.log")
MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")
MODEL_LIVE = joblib.load("ml/models/iforest_live.joblib")

# Parse all live records with timestamp and src_ip
rows = []
with open(LIVE_LOG) as f:
    for line in f:
        if line.startswith("#"):
            continue
        p = line.strip().split("\t")
        if len(p) < 20:
            continue
        try:
            ts = float(p[0])
            proto = p[6].lower()
            state = p[11].upper()
            row = {
                "ts": ts,
                "src_ip": p[2],
                "duration":        float(p[8])  if p[8]  not in ("-","") else 0.0,
                "orig_bytes":      float(p[9])  if p[9]  not in ("-","") else 0.0,
                "resp_bytes":      float(p[10]) if p[10] not in ("-","") else 0.0,
                "orig_pkts":       float(p[16]) if p[16] not in ("-","") else 0.0,
                "resp_pkts":       float(p[18]) if p[18] not in ("-","") else 0.0,
                "proto_tcp":       int(proto == "tcp"),
                "proto_udp":       int(proto == "udp"),
                "proto_icmp":      int(proto == "icmp"),
                "conn_state_S0":   int(state == "S0"),
                "conn_state_SF":   int(state == "SF"),
                "conn_state_REJ":  int(state == "REJ"),
                "conn_state_RSTO": int(state == "RSTO"),
            }
            rows.append(row)
        except Exception:
            continue

df = pd.DataFrame(rows)
n_total = len(df)

# --- Model mtime for split ---
model_mtime = os.stat("ml/models/iforest_live.joblib").st_mtime
df_before_train = df[df["ts"] < model_mtime]
df_held_out = df[df["ts"] >= model_mtime]

def iforest_stats_on(model, X_df, label, threshold=-0.1):
    X = X_df[FEATURE_COLS].fillna(0).astype(float).values
    scores = model.decision_function(X)
    preds = model.predict(X)
    flags = int((scores < threshold).sum())
    anomalies = int((preds == -1).sum())
    return {
        "label": label,
        "n": len(X_df),
        "anomalies_contamination": anomalies,
        "below_-0.1": flags,
        "pct_below_-0.1": 100*flags/len(X_df) if len(X_df) else 0,
        "score_min": float(scores.min()) if len(scores) else 0,
        "score_mean": float(scores.mean()) if len(scores) else 0,
    }

print(f"Total records in current conn.log: {n_total}")
print(f"  Records in train window (ts < live model mtime): {len(df_before_train)}")
print(f"  Records after train boundary (held-out):          {len(df_held_out)}")
print()

# Full 1906-record population (clearly labelled as different session)
print("=== FULL CURRENT LOG (1906-record set — different session from original 432) ===")
for model, name in [(MODEL_UNSW, "UNSW-corrected"), (MODEL_LIVE, "Live-retrained")]:
    s = iforest_stats_on(model, df, name)
    print(f"  {name}: {s['below_-0.1']}/{s['n']} below -0.1 ({s['pct_below_-0.1']:.2f}%)")

# Held-out set (records after live model training)
if len(df_held_out) > 0:
    print()
    print(f"=== OUT-OF-SAMPLE SET ({len(df_held_out)} records after live model training boundary) ===")
    print("Ground truth: src_ip == '10.10.0.2' = attack; others = background")
    X_ho = df_held_out[FEATURE_COLS].fillna(0).astype(float).values
    gt_ho = (df_held_out["src_ip"] == "10.10.0.2").astype(int).values
    print(f"  Positives (Kali): {gt_ho.sum()},  Negatives (background): {(1-gt_ho).sum()}")

    for model, name in [(MODEL_UNSW, "UNSW-corrected"), (MODEL_LIVE, "Live-retrained")]:
        scores = model.decision_function(X_ho)
        flags = (scores < -0.1).astype(int)
        TP = int(((flags == 1) & (gt_ho == 1)).sum())
        FP = int(((flags == 1) & (gt_ho == 0)).sum())
        TN = int(((flags == 0) & (gt_ho == 0)).sum())
        FN = int(((flags == 0) & (gt_ho == 1)).sum())
        prec = TP / (TP+FP) if (TP+FP) > 0 else 0
        rec  = TP / (TP+FN) if (TP+FN) > 0 else 0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0
        total_flags = TP + FP
        print(f"  {name}: TP={TP} FP={FP} TN={TN} FN={FN} | P={prec:.3f} R={rec:.3f} F1={f1:.3f}")
        print(f"    Flag rate: {total_flags}/{len(X_ho)} ({100*total_flags/len(X_ho):.1f}%)")
else:
    print("No held-out records (all records pre-date the live model)")
PYEOF
echo ""

# ── Part 5: Ground-truth P/R on archived conn.log ─────────────────────────────
echo "$SEP"
echo "PART 5: GROUND-TRUTH P/R ON ZEEK CONN.LOG ARCHIVE (with Wilson CIs)"
echo "$SEP"
python3 - <<'PYEOF'
import joblib, glob, gzip
import numpy as np
from pathlib import Path

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")
MODEL_LIVE = joblib.load("ml/models/iforest_live.joblib")
MODEL_RF   = joblib.load("ml/models/rf_attack_type.joblib")

def wilson_ci(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    margin = z * ((p*(1-p)/n + z**2/(4*n**2))**0.5) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))

def parse_conn_log(path):
    """Parse a Zeek conn.log or conn.log.gz into rows."""
    rows = []
    opener = gzip.open if str(path).endswith('.gz') else open
    try:
        with opener(path, 'rt') as f:
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
                        "ts":       float(p[0]),
                        "src_ip":   p[2],
                        "duration":        float(p[8])  if p[8]  not in ("-","") else 0.0,
                        "orig_bytes":      float(p[9])  if p[9]  not in ("-","") else 0.0,
                        "resp_bytes":      float(p[10]) if p[10] not in ("-","") else 0.0,
                        "orig_pkts":       float(p[16]) if p[16] not in ("-","") else 0.0,
                        "resp_pkts":       float(p[18]) if p[18] not in ("-","") else 0.0,
                        "proto_tcp":       int(proto == "tcp"),
                        "proto_udp":       int(proto == "udp"),
                        "proto_icmp":      int(proto == "icmp"),
                        "conn_state_S0":   int(state == "S0"),
                        "conn_state_SF":   int(state == "SF"),
                        "conn_state_REJ":  int(state == "REJ"),
                        "conn_state_RSTO": int(state == "RSTO"),
                    }
                    rows.append(row)
                except Exception:
                    continue
    except Exception as e:
        print(f"  Warning: could not parse {path}: {e}")
    return rows

# Collect all available Zeek conn logs (archived + current)
ZEEK_LOG_DIR = Path("/opt/zeek/logs")
all_logs = sorted(ZEEK_LOG_DIR.rglob("conn*.log*"))
# Exclude current (will add separately)
archive_logs = [p for p in all_logs
                if "current" not in str(p) and not str(p).endswith(".tmp")]

print(f"Found {len(archive_logs)} archived conn log(s):")
for p in archive_logs:
    print(f"  {p}")

# Load all records
rows = []
for p in archive_logs:
    r = parse_conn_log(p)
    rows.extend(r)
    print(f"  Loaded {len(r)} records from {p.name}")

# Also include current log
current_rows = parse_conn_log(ZEEK_LOG_DIR / "current" / "conn.log")
rows.extend(current_rows)
print(f"  Loaded {len(current_rows)} records from current/conn.log")

print(f"\nTotal records across all logs: {len(rows):,}")

# Deduplicate by (ts, src_ip) to avoid double-counting if current overlaps archive
seen = set()
deduped = []
for row in rows:
    key = (round(row["ts"], 6), row["src_ip"])
    if key not in seen:
        seen.add(key)
        deduped.append(row)

print(f"After deduplication: {len(deduped):,} records")

# Assign ground truth labels
import numpy as np
X = np.array([[r[f] for f in FEATURE_COLS] for r in deduped], dtype=float)
gt = np.array([1 if r["src_ip"] == "10.10.0.2" else 0 for r in deduped])
n_pos = gt.sum()
n_neg = len(gt) - n_pos
print(f"Ground truth: {n_pos} attack (10.10.0.2), {n_neg} background")

def evaluate_iforest(model, X, gt, label, threshold=-0.1):
    scores = model.decision_function(X)
    flags  = (scores < threshold).astype(int)
    TP = int(((flags==1) & (gt==1)).sum())
    FP = int(((flags==1) & (gt==0)).sum())
    TN = int(((flags==0) & (gt==0)).sum())
    FN = int(((flags==0) & (gt==1)).sum())
    prec = TP/(TP+FP) if (TP+FP) else 0
    rec  = TP/(TP+FN) if (TP+FN) else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0
    prec_ci = wilson_ci(TP, TP+FP)
    rec_ci  = wilson_ci(TP, TP+FN)
    print(f"\n  {label}")
    print(f"    TP={TP}  FP={FP}  TN={TN}  FN={FN}")
    print(f"    Precision: {prec:.3f}  [95% CI: {prec_ci[0]:.3f}–{prec_ci[1]:.3f}]  (n={TP+FP})")
    print(f"    Recall:    {rec:.3f}  [95% CI: {rec_ci[0]:.3f}–{rec_ci[1]:.3f}]  (n={TP+FN})")
    print(f"    F1:        {f1:.3f}")
    flag_rate = (TP+FP)/len(gt)
    print(f"    Flag rate: {TP+FP}/{len(gt)} ({100*flag_rate:.2f}%)")

print("\n=== IForest Ground-truth Evaluation (threshold = -0.1) ===")
evaluate_iforest(MODEL_UNSW, X, gt, "UNSW-NB15 baseline (corrected encoding)")
evaluate_iforest(MODEL_LIVE, X, gt, "Live-retrained IForest")

# RF on all records
print("\n=== RF Attack-type Distribution on all records ===")
rf_preds = MODEL_RF.predict(X)
from collections import Counter
cnt = Counter(rf_preds)
total = len(rf_preds)
for cls, n in sorted(cnt.items(), key=lambda x: -x[1]):
    print(f"  {cls:<22} {n:>6}  ({100*n/total:.2f}%)")
PYEOF

echo ""
echo "$SEP"
echo "DONE — paste full output above to Claude"
echo "$SEP"
