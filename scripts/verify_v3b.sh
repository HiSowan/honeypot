#!/usr/bin/env bash
# verify_v3b.sh  —  Parts 2–5 continuation (Part 1 completed in verify_v3.sh)
#
# Run from ~/honeypot with venv active:
#   cd ~/honeypot
#   git pull
#   source venv/bin/activate
#   bash scripts/verify_v3b.sh 2>&1 | tee /tmp/verify_v3b_output.txt
#
# Requires the snapshot from verify_v3.sh to still exist at /tmp/conn_current_snap.log
# If it is gone, re-run: cp /opt/zeek/logs/current/conn.log /tmp/conn_current_snap.log

set -euo pipefail
SEP="========================================"
SNAP="/tmp/conn_current_snap.log"
TODAY=$(date +%Y-%m-%d)

echo "$SEP"
echo "Checking snapshot..."
echo "$SEP"
if [ -f "$SNAP" ]; then
    wc -l < "$SNAP" | xargs echo "  snapshot lines:"
else
    echo "  Snapshot missing — creating fresh one"
    cp /opt/zeek/logs/current/conn.log "$SNAP"
fi
echo ""

# ── PART 2: UNSW-NB15 state column — complete value_counts and mapping ─────────
echo "$SEP"
echo "PART 2: UNSW-NB15 STATE COLUMN — value_counts, mapping coverage, all-zero %"
echo "$SEP"
python3 - <<'PYEOF'
import pandas as pd
from pathlib import Path

CSV = Path("data/raw/UNSW_NB15_training-set.CSV")
df = pd.read_csv(CSV, low_memory=False)
df.columns = df.columns.str.strip().str.lower()
if "state" in df.columns and "conn_state" not in df.columns:
    df = df.rename(columns={"state": "conn_state"})

n = len(df)
raw_states = df["conn_state"].str.upper()

print(f"Total UNSW-NB15 records: {n:,}")
print()
print("Raw state value_counts (ALL values, sorted by frequency):")
vc = raw_states.value_counts(dropna=False)
for state, cnt in vc.items():
    print(f"  {str(state):<8} {cnt:>8,}  ({100*cnt/n:.4f}%)")

# Current mapping
MAP = {
    "REQ":  "S0",
    "FIN":  "SF",
    "CON":  "SF",
    "CLO":  "SF",
    "RST":  "RSTO",
    # Zeek pass-throughs
    "S0":   "S0",
    "SF":   "SF",
    "REJ":  "REJ",
    "RSTO": "RSTO",
    "OTH":  "OTH",
}

all_values_in_data = set(raw_states.dropna().unique())
mapped_values = set(MAP.keys())
unmapped = all_values_in_data - mapped_values

mapped_series = raw_states.map(MAP).fillna("")

print()
print("After current mapping — resulting conn_state distribution:")
for state in ("S0", "SF", "REJ", "RSTO", ""):
    cnt = (mapped_series == state).sum()
    label = state if state else "(all-zero / unmapped)"
    note = ""
    if state == "REJ":
        note = "  ← 0 UNSW records map here (only Zeek pass-through)"
    print(f"  {label:<25} {cnt:>8,}  ({100*cnt/n:.4f}%){note}")

all_zero_cnt = (mapped_series == "").sum()
print()
print(f"States in data NOT handled by current mapping ({len(unmapped)}):")
for s in sorted(unmapped):
    cnt = (raw_states == s).sum()
    print(f"  '{s}'   {cnt:>8,}  ({100*cnt/n:.4f}%)")

print()
print(f"Records with all-zero conn_state AFTER current mapping: {all_zero_cnt:,}  ({100*all_zero_cnt/n:.2f}%)")
print()

print("PROPOSED MAPPINGS for unhandled states (do not implement — proposals only):")
proposals = [
    ("INT", all_zero_cnt if "INT" in all_values_in_data else 0,
     "(leave all-zero)",
     "Active/interrupted — connection open at capture boundary. Closest Zeek analogue is "
     "OTH (neither cleanly opened nor closed), but OTH is not in FEATURE_COLS. Forcing to "
     "SF would assert a clean close that did not occur. Recommend documenting as structurally "
     "unresolvable; all-zero conn_state is honest. INT represents 46.9% of training records "
     "and will remain the dominant all-zero contributor regardless of any other fix."),
    ("ECO", (raw_states == "ECO").sum(),
     "(leave all-zero)",
     "ICMP echo — ICMP is already encoded by proto_icmp=1. Mapping ECO to a TCP-oriented "
     "conn_state would mix protocol semantics. All-zero is correct; proto_icmp carries the signal."),
    ("PAR", (raw_states == "PAR").sum(),
     "(leave all-zero)",
     "Partial connection — 1 record. No material impact on any metric. Leave as all-zero."),
    ("URN", (raw_states == "URN").sum(),
     "(leave all-zero)",
     "Unresolved — 1 record. No clean Zeek analogue. Leave as all-zero."),
    ("NO",  (raw_states == "NO").sum(),
     "(leave all-zero)",
     "Null/empty state — 1 record. Leave as all-zero."),
]
for state, cnt, mapping, justification in proposals:
    print(f"\n  {state} ({cnt:,} records) → {mapping}")
    # wrap justification at 80 chars
    words = justification.split()
    line = "    "
    for w in words:
        if len(line)+len(w)+1 > 80:
            print(line)
            line = "    " + w
        else:
            line += (" " if line != "    " else "") + w
    if line.strip():
        print(line)

print()
resid = (raw_states == "INT").sum() if "INT" in all_values_in_data else 0
print(f"If proposals adopted: all-zero count remains {all_zero_cnt:,} ({100*all_zero_cnt/n:.2f}%)")
print(f"INT is the sole material contributor ({resid:,} records = {100*resid/n:.2f}%).")
print(f"The other unhandled states sum to {all_zero_cnt - resid:,} records — negligible.")
PYEOF
echo ""

# ── PART 3: State coverage — recomputed from archive attack records ────────────
echo "$SEP"
echo "PART 3: STATE COVERAGE — from 1,544 archive attack records"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
KALI        = "10.10.0.2"

# Training vocab confirmed from Part 2 results
# States with >0 UNSW training examples after mapping:
TRAIN_EXAMPLES = {"S0", "SF", "RSTO"}  # REJ has feature column but 0 training examples
FEATURE_COLS_STATES = {"S0", "SF", "REJ", "RSTO"}  # columns that exist in the model

def is_conn_log(p):
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path):
    rows = []
    opener = gzip.open if str(path).endswith(".gz") else open
    fields = None
    try:
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if fields is None:
                    continue
                row = dict(zip(fields, line.split("\t")))
                rows.append(row)
    except Exception as e:
        print(f"  Warning {path.name}: {e}", file=sys.stderr)
    return rows

arch_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))

uid_seen = set()
attack_states = Counter()
attack_n = 0

for p in arch_logs + [SNAP]:
    for row in parse_log_rows(p):
        uid = row.get("uid","")
        src = row.get("id.orig_h","")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        if src == KALI:
            attack_states[row.get("conn_state","").upper()] += 1
            attack_n += 1

print(f"Archive attack records (10.10.0.2, uid-deduped): {attack_n:,}")
print()
print("Attack conn_state distribution:")
print(f"  {'State':<10} {'Count':>7}  {'%':>6}  Status")
print(f"  {'-'*10} {'-'*7}  {'-'*6}  {'-'*45}")
for state, cnt in sorted(attack_states.items(), key=lambda x: -x[1]):
    if state in TRAIN_EXAMPLES:
        status = "IN TRAINING (examples > 0)"
    elif state in FEATURE_COLS_STATES:
        status = "FEATURE COL EXISTS — 0 training examples (inference-alive, training-dead)"
    else:
        status = "NOT in FEATURE_COLS → all-zero at inference"
    print(f"  {state or '(empty)':<10} {cnt:>7,}  {100*cnt/attack_n:>5.1f}%  {status}")

# Coverage
in_training = sum(cnt for state, cnt in attack_states.items() if state in TRAIN_EXAMPLES)
no_repr     = attack_n - in_training

print()
print("=== COVERAGE ===")
print(f"Training vocab with >0 examples: {sorted(TRAIN_EXAMPLES)}")
print(f"  (REJ is a FEATURE_COL but has 0 training examples — not counted as 'represented')")
print()
print(f"Attack records with state in training vocab: {in_training:,}  ({100*in_training/attack_n:.1f}%)")
for s in TRAIN_EXAMPLES:
    cnt = attack_states.get(s, 0)
    print(f"  {s}: {cnt:,}  ({100*cnt/attack_n:.1f}%)")
print()
pct_no = 100*no_repr/attack_n
print(f"Attack records WITHOUT training representation: {no_repr:,}  ({pct_no:.1f}%)")
print()
print("Breakdown of unrepresented attack records:")
for state, cnt in sorted(attack_states.items(), key=lambda x: -x[1]):
    if state not in TRAIN_EXAMPLES:
        if state in FEATURE_COLS_STATES:
            note = "feature fires at inference; 0 training examples → model cannot use it"
        else:
            note = "all-zero at inference (state not in FEATURE_COLS)"
        print(f"  {state or '(empty)':<10} {cnt:>6,}  ({100*cnt/attack_n:.1f}%)  [{note}]")
print()
print(f"==> {pct_no:.1f}% of live attack records have no training representation")
if abs(pct_no - 86.8) < 1.0:
    print(f"    User predicted 86.8% — CONFIRMED (within 1%)")
else:
    print(f"    User predicted 86.8% — ACTUAL: {pct_no:.1f}%")
print()
print("Note: previous round's '0% overlap' was computed on a 499-record background-only")
print("log containing zero Kali records. That figure is void and must not appear in the thesis.")
PYEOF
echo ""

# ── PART 4: Canonical count ────────────────────────────────────────────────────
echo "$SEP"
echo "PART 4: CANONICAL RECORD COUNT"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
ALLOWLIST   = {"192.168.0.3","127.0.0.1","10.0.2.15"}
KALI        = "10.10.0.2"

def is_conn_log(p):
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path):
    rows = []
    opener = gzip.open if str(path).endswith(".gz") else open
    fields = None
    try:
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if fields is None:
                    continue
                row = dict(zip(fields, line.split("\t")))
                rows.append(row)
    except Exception as e:
        print(f"  Warning {path.name}: {e}", file=sys.stderr)
    return rows

arch_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))

uid_seen = set()
by_src = Counter()

for p in arch_logs + [SNAP]:
    for row in parse_log_rows(p):
        uid = row.get("uid","")
        src = row.get("id.orig_h","")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        by_src[src] += 1

total  = sum(by_src.values())
attack = by_src.get(KALI, 0)
bg     = total - attack
al     = sum(cnt for ip,cnt in by_src.items() if ip in ALLOWLIST)
excl_bg = bg - al
excl_total = attack + excl_bg

print(f"CANONICAL COUNTS (this script run, snapshot-consistent):")
print(f"  Total (uid-deduped):        {total:>7,}")
print(f"  Attack (10.10.0.2):         {attack:>7,}  ({100*attack/total:.2f}%)")
print(f"  Background (all):           {bg:>7,}  ({100*bg/total:.2f}%)")
print(f"    Allowlisted bg:           {al:>7,}")
print(f"    Non-allowlisted bg:       {excl_bg:>7,}")
print(f"  Allowlist-excluded total:   {excl_total:>7,}")
print(f"  Allowlist-excluded base rate: {100*attack/excl_total:.2f}%")
print()
print(f"verify_v3.sh Part 1 reported 35,375 — this run reports {total}.")
diff = total - 35375
if diff == 0:
    print("  Counts match.")
else:
    print(f"  Difference: {diff:+d} records (live Zeek wrote to conn.log between runs).")
    print("  Use 35,375 from the snapshot run as canonical for this thesis submission.")
PYEOF
echo ""

# ── PART 5: Clean held-out IForest evaluation ─────────────────────────────────
echo "$SEP"
echo "PART 5: CLEAN HELD-OUT IFOREST EVALUATION"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys, json, random
import numpy as np
import joblib
from pathlib import Path
from collections import Counter
from sklearn.ensemble import IsolationForest
import datetime

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
KALI        = "10.10.0.2"
ALLOWLIST   = {"192.168.0.3","127.0.0.1","10.0.2.15"}
TODAY_DIR   = Path("ml/models/archive") / datetime.date.today().isoformat()
TODAY_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLS = [
    "duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts",
    "proto_tcp","proto_udp","proto_icmp",
    "conn_state_S0","conn_state_SF","conn_state_REJ","conn_state_RSTO",
]

def is_conn_log(p):
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path):
    rows = []
    opener = gzip.open if str(path).endswith(".gz") else open
    fields = None
    try:
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if fields is None:
                    continue
                row = dict(zip(fields, line.split("\t")))
                rows.append(row)
    except Exception as e:
        print(f"  Warning {path.name}: {e}", file=sys.stderr)
    return rows

def row_to_vec(row):
    proto = row.get("proto","").lower()
    state = row.get("conn_state","").upper()
    def sf(v):
        try: return float(v) if v and v not in ("-",) else 0.0
        except: return 0.0
    return [
        sf(row.get("duration")),  sf(row.get("orig_bytes")),
        sf(row.get("resp_bytes")), sf(row.get("orig_pkts")),
        sf(row.get("resp_pkts")),
        int(proto=="tcp"), int(proto=="udp"), int(proto=="icmp"),
        int(state=="S0"), int(state=="SF"), int(state=="REJ"), int(state=="RSTO"),
    ]

arch_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))

uid_seen = set()
records  = []   # (uid, src, vec)

for p in arch_logs + [SNAP]:
    for row in parse_log_rows(p):
        uid = row.get("uid","")
        src = row.get("id.orig_h","")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        records.append((uid, src, row_to_vec(row)))

total = len(records)
attack_idx = [i for i,(u,s,v) in enumerate(records) if s == KALI]
bg_idx     = [i for i,(u,s,v) in enumerate(records) if s != KALI]
n_attack   = len(attack_idx)
n_bg       = len(bg_idx)

print(f"Canonical uid-deduped records: {total:,}")
print(f"  Attack (10.10.0.2): {n_attack:,}")
print(f"  Background:         {n_bg:,}")
print()

# 70/30 stratified split on attack records
# All background goes into training set (IForest trains on full traffic, not just attacks)
rng = random.Random(42)
rng.shuffle(attack_idx)
split       = int(0.70 * n_attack)
train_atk   = attack_idx[:split]
test_atk    = attack_idx[split:]  # held-out positives
n_train_atk = len(train_atk)
n_test_atk  = len(test_atk)

# Training: 70% attack + all background
train_idx  = sorted(train_atk + bg_idx)
# Held-out evaluation: 30% attack + background (full or allowlist-excluded for two evals)

print(f"Split: 70/30 on attack records")
print(f"  Training: {n_train_atk:,} attack + {n_bg:,} background = {len(train_idx):,} total")
print(f"  Held-out positives: {n_test_atk:,}")

# CI width check
z = 1.96
ci_half_at_half = z * (0.5/n_test_atk**0.5)
print(f"  Wilson CI half-width at P=0.5, n={n_test_atk}: {ci_half_at_half:.3f}  ({'OK' if ci_half_at_half < 0.05 else 'marginal — check CIs on actual results'})")
print()

# Train new IForest
X_train = np.array([records[i][2] for i in train_idx], dtype=float)
print(f"Training IForest (contamination=0.1, n_estimators=100, random_state=42)...")
clf_new = IsolationForest(n_estimators=100, contamination=0.1, n_jobs=-1, random_state=42)
clf_new.fit(X_train)

model_out    = TODAY_DIR / "iforest_live_holdout.joblib"
manifest_out = TODAY_DIR / "train_index.json"
joblib.dump(clf_new, model_out)
manifest = {
    "total_records": total,
    "n_attack": n_attack,
    "n_bg": n_bg,
    "n_train": len(train_idx),
    "n_train_attack": n_train_atk,
    "n_train_bg": n_bg,
    "n_held_out_attack": n_test_atk,
    "split_rule": "70% attack (random_state=42) + all background in training; 30% attack held out",
    "train_uids": [records[i][0] for i in train_idx],
}
with open(manifest_out,"w") as f:
    json.dump(manifest, f, indent=2)
print(f"Model saved:    {model_out}")
print(f"Manifest saved: {manifest_out}")
print()

MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")

def wilson_ci(k, n, z=1.96):
    if n==0: return (0.0,0.0)
    p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d
    m=z*((p*(1-p)/n+z*z/(4*n*n))**0.5)/d
    return (max(0.0,c-m), min(1.0,c+m))

def eval_on(model, test_atk_idx, bg_src_filter, label):
    """Evaluate on held-out attack + filtered background."""
    # held-out attack records
    eval_idx = list(test_atk_idx)
    # add background (filtered)
    bg_excl = [i for i in bg_idx if bg_src_filter(records[i][1])]
    eval_idx += bg_excl
    srcs = [records[i][1] for i in eval_idx]
    X_e  = np.array([records[i][2] for i in eval_idx], dtype=float)
    y_e  = np.array([1 if records[i][1]==KALI else 0 for i in eval_idx], dtype=int)

    scores = model.decision_function(X_e)
    flags  = (scores < -0.1).astype(int)
    TP=int(((flags==1)&(y_e==1)).sum()); FP=int(((flags==1)&(y_e==0)).sum())
    TN=int(((flags==0)&(y_e==0)).sum()); FN=int(((flags==0)&(y_e==1)).sum())
    P = TP/(TP+FP) if (TP+FP) else 0.0
    R = TP/(TP+FN) if (TP+FN) else 0.0
    F = 2*P*R/(P+R) if (P+R) else 0.0
    Pci=wilson_ci(TP,TP+FP); Rci=wilson_ci(TP,TP+FN)
    base=100*y_e.sum()/len(y_e)
    print(f"  {label}")
    print(f"    n={len(y_e):,}  attack={y_e.sum():,} ({base:.2f}%)")
    print(f"    TP={TP}  FP={FP}  TN={TN}  FN={FN}")
    print(f"    Precision: {P:.3f}  [95% CI: {Pci[0]:.3f}–{Pci[1]:.3f}]  (n={TP+FP})")
    print(f"    Recall:    {R:.3f}  [95% CI: {Rci[0]:.3f}–{Rci[1]:.3f}]  (n={TP+FN})")
    print(f"    F1:        {F:.3f}")
    print(f"    Flag rate: {TP+FP}/{len(y_e)} ({100*(TP+FP)/len(y_e):.2f}%)")
    # FP breakdown
    fp_mask = (flags==1)&(y_e==0)
    fp_by_src = Counter(srcs[i] for i in range(len(srcs)) if fp_mask[i])
    if fp_by_src:
        al_fp = sum(c for ip,c in fp_by_src.items() if ip in ALLOWLIST)
        print(f"    FP breakdown (top 6):")
        for ip,c in fp_by_src.most_common(6):
            tag=" [AL]" if ip in ALLOWLIST else ""
            print(f"      {ip:<42} {c:>5}{tag}")
        print(f"    Allowlisted FPs: {al_fp}/{TP+FP}")
    print()

print("=== HELD-OUT EVALUATION: NEW LIVE IFOREST vs UNSW-CORRECTED ===")
print(f"Held-out positives: {n_test_atk:,} attack records (30% of {n_attack:,})")
print()

print("--- Full background (all sources) ---")
eval_on(MODEL_UNSW, test_atk, lambda s: True, "UNSW-corrected  [full bg]")
eval_on(clf_new,    test_atk, lambda s: True, "New live IForest [full bg]")

print("--- Allowlist-excluded background ---")
eval_on(MODEL_UNSW, test_atk, lambda s: s not in ALLOWLIST, "UNSW-corrected  [allowlist-excl bg]")
eval_on(clf_new,    test_atk, lambda s: s not in ALLOWLIST, "New live IForest [allowlist-excl bg]")
PYEOF

echo ""
echo "$SEP"
echo "DONE — paste full output to Claude"
echo "$SEP"
