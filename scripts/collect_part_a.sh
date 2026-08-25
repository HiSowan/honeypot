#!/usr/bin/env bash
# Part A / C / D data collection for thesis retraining round.
# Run from ~/honeypot with venv active:
#
#   cd ~/honeypot
#   source venv/bin/activate
#   bash scripts/collect_part_a.sh 2>&1 | tee /tmp/part_a_output.txt
#
# Then: cat /tmp/part_a_output.txt  (paste full output to Claude)

set -euo pipefail
SEP="========================================"

# ── Part D: exact versions ────────────────────────────────────────────────────
echo "$SEP"
echo "SECTION: VERSIONS"
echo "$SEP"
echo "scikit-learn:        $(pip show scikit-learn 2>/dev/null | grep '^Version' | awk '{print $2}')"
echo "promtail:            $(/opt/promtail/promtail --version 2>&1 | head -1)"
echo "iptables-persistent: $(dpkg -l iptables-persistent 2>/dev/null | awk '/^ii/{print $3}' || echo 'NOT INSTALLED')"
echo ""

# ── Part A: Encoding verification ─────────────────────────────────────────────
echo "$SEP"
echo "SECTION: ENCODING VERIFICATION (conn_state value_counts before/after fix)"
echo "$SEP"
python3 - <<'PYEOF'
import sys, pandas as pd
from pathlib import Path

CSV = Path("data/raw/UNSW_NB15_training-set.CSV")
if not CSV.exists():
    print(f"ERROR: {CSV} not found — retraining cannot proceed")
    sys.exit(1)

df = pd.read_csv(CSV, low_memory=False)
df.columns = df.columns.str.strip().str.lower()

# Rename to internal name (col may be 'state' in UNSW)
COL_MAP = {"state": "conn_state", "dur": "duration", "sbytes": "orig_bytes",
           "dbytes": "resp_bytes", "spkts": "orig_pkts", "dpkts": "resp_pkts"}
df = df.rename(columns=COL_MAP)

print(f"Total records: {len(df):,}")
print(f"\nRaw conn_state value_counts (top 12):")
print(df["conn_state"].str.upper().value_counts().head(12).to_string())

# ─ BEFORE: no mapping (what old preprocess.py did) ─
print("\n=== BEFORE fix (Zeek vocab applied directly to Argus values) ===")
for state in ("S0", "SF", "REJ", "RSTO"):
    col = (df["conn_state"].str.upper() == state).astype(int)
    print(f"  conn_state_{state}: sum={col.sum():,}  (all zero? {col.sum()==0})")

# ─ AFTER: with Argus→Zeek mapping ─
print("\n=== AFTER fix (Argus→Zeek map applied first) ===")
MAP = {"REQ": "S0", "FIN": "SF", "CON": "SF", "CLO": "SF", "RST": "RSTO"}
mapped = df["conn_state"].str.upper().map(MAP).fillna("")
for state in ("S0", "SF", "REJ", "RSTO"):
    col = (mapped == state).astype(int)
    print(f"  conn_state_{state}: sum={col.sum():,}")
PYEOF

echo ""

# ── Part A: Retrain RF ────────────────────────────────────────────────────────
echo "$SEP"
echo "SECTION: RETRAIN RANDOM FOREST"
echo "$SEP"
python3 -m ml.train_rf data/raw/UNSW_NB15_training-set.CSV
echo ""

# ── Part A: Retrain UNSW IForest baseline ─────────────────────────────────────
echo "$SEP"
echo "SECTION: RETRAIN IFOREST (UNSW-NB15 baseline)"
echo "$SEP"
python3 -m ml.train_iforest data/raw/UNSW_NB15_training-set.CSV
echo ""

# ── Part A: Full eval ─────────────────────────────────────────────────────────
echo "$SEP"
echo "SECTION: EVAL_CH5 (full evaluation)"
echo "$SEP"
python3 ml/eval_ch5.py
echo ""

# ── Part C: Shadow mode recompute ─────────────────────────────────────────────
echo "$SEP"
echo "SECTION: SHADOW_MODE.CSV RECOMPUTE (Part C)"
echo "$SEP"
python3 - <<'PYEOF'
import csv
from collections import Counter

SHADOW = "/var/log/honeypot/shadow_mode.csv"
total_rows = 0
wb_counts  = Counter()   # would_block=True per IP
wb_false   = 0

try:
    with open(SHADOW, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            if row.get('would_block', '').strip() == 'True':
                wb_counts[row['src_ip'].strip()] += 1
            else:
                wb_false += 1
except FileNotFoundError:
    print(f"ERROR: {SHADOW} not found")
    raise

wb_total = sum(wb_counts.values())
print(f"Total rows (excl header):  {total_rows:,}")
print(f"would_block=False:         {wb_false:,}")
print(f"would_block=True:          {wb_total:,}")
print()
print("would_block=True per source IP (sorted by count):")
for ip, n in sorted(wb_counts.items(), key=lambda x: -x[1]):
    pct = 100 * n / wb_total if wb_total else 0
    print(f"  {ip:<42} {n:>5}  ({pct:.1f}%)")

# Explicit attacker vs FP breakdown
attacker = wb_counts.get('10.10.0.2', 0)
loopback  = wb_counts.get('127.0.0.1', 0)
fp_total  = wb_total - attacker
print()
print(f"Kali attacker 10.10.0.2 blocks:  {attacker}")
print(f"127.0.0.1 loopback blocks:        {loopback}")
print(f"Non-attacker (FP) blocks total:   {fp_total}")
if wb_total:
    print(f"False-positive rate:              {100*fp_total/wb_total:.1f}%")
PYEOF

echo ""
echo "$SEP"
echo "DONE — paste the full output above to Claude"
echo "$SEP"
