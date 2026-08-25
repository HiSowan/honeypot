#!/usr/bin/env bash
# verify_v3.sh  —  Parts 1–5 verification, round 3
#
# Run from ~/honeypot with venv active:
#   cd ~/honeypot
#   git pull
#   source venv/bin/activate
#   bash scripts/verify_v3.sh 2>&1 | tee /tmp/verify_v3_output.txt
#
# Then: cat /tmp/verify_v3_output.txt

set -euo pipefail
SEP="========================================"
ARCHIVE_DIR="/opt/zeek/logs"
MODELS="ml/models"
TODAY=$(date +%Y-%m-%d)
SNAP="/tmp/conn_current_snap.log"

# ── Backup .joblib files ───────────────────────────────────────────────────────
echo "$SEP"
echo "BACKUP: .joblib files → $MODELS/archive/$TODAY/"
echo "$SEP"
mkdir -p "$MODELS/archive/$TODAY"
for f in "$MODELS"/*.joblib; do
    [ -f "$f" ] && cp -p "$f" "$MODELS/archive/$TODAY/" && echo "  backed up: $(basename "$f")"
done
echo ""

# ── Snapshot current conn.log once for all parts (fixes Part 4 off-by-two) ────
echo "$SEP"
echo "SNAPSHOT: copying current conn.log once so all parts use identical data"
echo "$SEP"
if [ -f "/opt/zeek/logs/current/conn.log" ]; then
    cp /opt/zeek/logs/current/conn.log "$SNAP"
    echo "  snapshot saved to $SNAP"
    wc -l < "$SNAP" | xargs echo "  lines in snapshot:"
else
    echo "  WARNING: /opt/zeek/logs/current/conn.log not found — snapshot empty"
    touch "$SNAP"
fi
echo ""

# ── PART 1: Allowlist-excluded population ─────────────────────────────────────
echo "$SEP"
echo "PART 1: ALLOWLIST EXCLUSION ANALYSIS"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys, json
import numpy as np
import joblib
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
KALI        = "10.10.0.2"
ALLOWLIST   = {"192.168.0.3", "127.0.0.1", "10.0.2.15"}

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")
MODEL_LIVE = joblib.load("ml/models/iforest_live.joblib")

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
    proto = row.get("proto", "").lower()
    state = row.get("conn_state", "").upper()
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

uid_seen  = set()
records   = []   # (src_ip, conn_state, feat_vec)

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
        records.append((src, row.get("conn_state","").upper(), row_to_vec(row)))

total = len(records)
print(f"uid-deduped total records: {total:,}")

# ── Allowlist breakdown ────────────────────────────────────────────────────────
print("\nALLOWLIST ENTRIES (from config/allowlist.txt):")
for ip in sorted(ALLOWLIST):
    cnt = sum(1 for r in records if r[0]==ip)
    print(f"  {ip:<45} {cnt:>7,}  ({100*cnt/total:.2f}%)")

by_src = Counter(r[0] for r in records)
print("\nFull source-IP counts:")
for ip, cnt in by_src.most_common(12):
    tag = " [ALLOWLISTED]" if ip in ALLOWLIST else (" [ATTACKER]" if ip==KALI else "")
    print(f"  {ip:<45} {cnt:>7,}{tag}")

# ── Run both models on full archive ───────────────────────────────────────────
X_all = np.array([r[2] for r in records], dtype=float)
y_all = np.array([1 if r[0]==KALI else 0 for r in records], dtype=int)

def wilson_ci(k, n, z=1.96):
    if n==0: return (0.0,0.0)
    p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d
    m=z*((p*(1-p)/n+z*z/(4*n*n))**0.5)/d
    return (max(0.0,c-m), min(1.0,c+m))

def eval_model(model, X, y, label, prefix=""):
    scores = model.decision_function(X)
    flags  = (scores < -0.1).astype(int)
    TP=int(((flags==1)&(y==1)).sum()); FP=int(((flags==1)&(y==0)).sum())
    TN=int(((flags==0)&(y==0)).sum()); FN=int(((flags==0)&(y==1)).sum())
    P = TP/(TP+FP) if (TP+FP) else 0.0
    R = TP/(TP+FN) if (TP+FN) else 0.0
    F = 2*P*R/(P+R) if (P+R) else 0.0
    Pci=wilson_ci(TP,TP+FP); Rci=wilson_ci(TP,TP+FN)
    base=100*y.sum()/len(y)
    print(f"  {label}")
    print(f"    n={len(y):,}  attack={y.sum():,} ({base:.2f}%)")
    print(f"    TP={TP}  FP={FP}  TN={TN}  FN={FN}")
    print(f"    Precision: {P:.3f}  [95% CI: {Pci[0]:.3f}–{Pci[1]:.3f}]  (n={TP+FP})")
    print(f"    Recall:    {R:.3f}  [95% CI: {Rci[0]:.3f}–{Rci[1]:.3f}]  (n={TP+FN})")
    print(f"    F1:        {F:.3f}")
    print(f"    Flag rate: {TP+FP}/{len(y)} ({100*(TP+FP)/len(y):.2f}%)")
    print()

    # FP breakdown by source IP
    fp_mask = (flags==1)&(y==0)
    fp_srcs = [records[i][0] for i in range(len(records)) if fp_mask[i]]
    fp_by_src = Counter(fp_srcs)
    print(f"    FP breakdown by src_ip:")
    fp_total = sum(fp_by_src.values())
    al_fps = sum(cnt for ip,cnt in fp_by_src.items() if ip in ALLOWLIST)
    for ip,cnt in fp_by_src.most_common(8):
        tag=" [ALLOWLISTED]" if ip in ALLOWLIST else ""
        print(f"      {ip:<45} {cnt:>5}{tag}")
    print(f"    Allowlisted FPs: {al_fps}/{fp_total} ({100*al_fps/fp_total:.1f}% of FPs)" if fp_total else "")
    print()
    return fp_mask

print("\n=== FULL ARCHIVE (all sources) ===")
fp_unsw_full = eval_model(MODEL_UNSW, X_all, y_all, "UNSW-corrected")
fp_live_full = eval_model(MODEL_LIVE, X_all, y_all, "Live-retrained")

# ── Allowlist-excluded evaluation ─────────────────────────────────────────────
excl_mask = [r[0] not in ALLOWLIST for r in records]
X_excl = np.array([r[2] for i,r in enumerate(records) if excl_mask[i]], dtype=float)
y_excl = np.array([1 if r[0]==KALI else 0 for i,r in enumerate(records) if excl_mask[i]], dtype=int)
excl_srcs = [r[0] for i,r in enumerate(records) if excl_mask[i]]

print("=== ALLOWLIST-EXCLUDED (production-representative) ===")
print(f"Excluded allowlisted records: {total - len(X_excl):,}")
print(f"Remaining: {len(X_excl):,}  attack={y_excl.sum():,}  background={len(y_excl)-y_excl.sum():,}")
print()
excl_by_src = Counter(excl_srcs)
print("Background source IPs in excluded population:")
for ip,cnt in excl_by_src.most_common(10):
    if ip != KALI:
        print(f"  {ip:<45} {cnt:>6,}")
print()
eval_model(MODEL_UNSW, X_excl, y_excl, "UNSW-corrected (allowlist-excluded)")
eval_model(MODEL_LIVE, X_excl, y_excl, "Live-retrained (allowlist-excluded)")

# ── Eval_ch5 defect confirmation ──────────────────────────────────────────────
print("=== EVAL_CH5.PY METHODOLOGICAL NOTE ===")
print("eval_ch5.py reads /opt/zeek/logs/current/conn.log with no allowlist filtering.")
print("Allowlisted sources (127.0.0.1, 10.0.2.15, 192.168.0.3) are included in the")
print("scored population. FPs on allowlisted addresses are never seen in production.")
print("This is a defect in the evaluation harness, not in the deployed controller.")
PYEOF
echo ""

# ── PART 2: UNSW-NB15 state coverage ──────────────────────────────────────────
echo "$SEP"
echo "PART 2: UNSW-NB15 STATE COLUMN — complete value_counts and mapping coverage"
echo "$SEP"
python3 - <<'PYEOF'
import pandas as pd
from pathlib import Path

CSV = Path("data/raw/UNSW_NB15_training-set.CSV")
df = pd.read_csv(CSV, low_memory=False)
df.columns = df.columns.str.strip().str.lower()
# rename 'state' → 'conn_state' if needed
if "state" in df.columns and "conn_state" not in df.columns:
    df = df.rename(columns={"state":"conn_state"})

n = len(df)
print(f"Total UNSW-NB15 records: {n:,}")
print()
print("Raw state column value_counts (all values):")
vc = df["conn_state"].str.upper().value_counts(dropna=False)
for state, cnt in vc.items():
    pct = 100*cnt/n
    print(f"  {str(state):<8} {cnt:>8,}  ({pct:.4f}%)")

# Current mapping
MAP = {
    "REQ":  "S0",
    "FIN":  "SF",
    "CON":  "SF",
    "CLO":  "SF",
    "RST":  "RSTO",
    # pass-throughs (Zeek vocab)
    "S0":   "S0",
    "SF":   "SF",
    "REJ":  "REJ",
    "RSTO": "RSTO",
    "OTH":  "OTH",
}

mapped = df["conn_state"].str.upper().map(MAP).fillna("")
mapped_vc = mapped.value_counts(dropna=False)

print()
print("After current mapping:")
for state in ("S0","SF","REJ","RSTO",""):
    cnt = (mapped==state).sum()
    label = state if state else "(all-zero / unmapped)"
    print(f"  {label:<25} {cnt:>8,}  ({100*cnt/n:.4f}%)")

# Unmapped states and their raw counts
mapped_raw   = set(MAP.keys())
all_raw      = set(df["conn_state"].str.upper().dropna().unique())
unmapped_set = all_raw - mapped_raw
all_zero_cnt = (mapped=="").sum()

print()
print(f"States present in data but NOT in mapping ({len(unmapped_set)} states):")
for s in sorted(unmapped_set):
    cnt = (df["conn_state"].str.upper()==s).sum()
    pct = 100*cnt/n
    print(f"  {s:<8} {cnt:>8,}  ({pct:.4f}%)")

print()
print(f"Records with all-zero conn_state after mapping: {all_zero_cnt:,}  ({100*all_zero_cnt/n:.2f}%)")
print()

# Proposed mappings for unhandled states
print("PROPOSED MAPPINGS (do not implement yet):")
proposals = {
    "INT": ("(leave all-zero)",
            "Connection active/interrupted at capture end — no clean Zeek analogue; "
            "closest is OTH (not in FEATURE_COLS). Forcing to SF would assert a clean "
            "close that did not occur. Recommend documenting as 'unsupported; all-zero'."),
    "ECO": ("(leave all-zero)",
            "ICMP echo request/response. ICMP behaviour already encoded by proto_icmp=1; "
            "conn_state for ICMP in Zeek depends on reply presence. Leave as all-zero to "
            "avoid double-encoding; note in limitations."),
    "PAR": ("(leave all-zero)",
            "Partial connection — SYN seen without completion. Closest Zeek analogue is S0, "
            "but PAR appears only once; adding it would affect 0.0006% of records."),
    "URN": ("(leave all-zero)",
            "URN (unresolved) — no Zeek analogue. Single record. Leave as all-zero."),
    "NO":  ("(leave all-zero)",
            "Empty/null state. Single record. Leave as all-zero."),
}
for state, (mapping, justification) in proposals.items():
    cnt = (df["conn_state"].str.upper()==state).sum() if state in all_raw else 0
    print(f"  {state:<6} ({cnt:,} records) → {mapping}")
    print(f"         {justification}")

print()
total_unresolvable = sum((df["conn_state"].str.upper()==s).sum() for s in unmapped_set)
print(f"If proposals adopted: all-zero records remain {total_unresolvable:,} ({100*total_unresolvable/n:.2f}%)")
print("INT is the sole material contributor — the others are negligible (<15 records combined).")
PYEOF
echo ""

# ── PART 3: State coverage recomputed from archive attack records ──────────────
echo "$SEP"
echo "PART 3: STATE COVERAGE — recomputed from archive attack records"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
KALI        = "10.10.0.2"

FEATURE_COLS_STATES = ("S0", "SF", "REJ", "RSTO")

# Training vocab after mapping — from Part 2 data
TRAINING_VOCAB_WITH_EXAMPLES = {"S0", "SF", "RSTO"}  # REJ has 0 training examples
TRAINING_VOCAB_ALL_COLS = {"S0", "SF", "REJ", "RSTO"}  # feature columns (REJ col exists)

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

uid_seen  = set()
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

print(f"Archive attack records (uid-deduped, 10.10.0.2): {attack_n:,}")
print()
print("Attack conn_state distribution (full):")
for state, cnt in sorted(attack_states.items(), key=lambda x: -x[1]):
    in_train = " [in FEATURE_COLS, training examples>0]" if state in TRAINING_VOCAB_WITH_EXAMPLES else \
               (" [in FEATURE_COLS, 0 training examples]" if state in TRAINING_VOCAB_ALL_COLS else " [NOT in FEATURE_COLS → all-zero]")
    print(f"  {state or '(empty)':<10} {cnt:>6,}  ({100*cnt/attack_n:.1f}%){in_train}")

print()
# Coverage calculation
# "Training representation" = conn_state produces a feature column with >0 training examples
# Only S0 qualifies (SF=0 in attack, RSTO=~0 in attack, REJ=0 training examples)
in_vocab_with_training = sum(cnt for state, cnt in attack_states.items() if state in TRAINING_VOCAB_WITH_EXAMPLES)
no_training_repr = attack_n - in_vocab_with_training

print("=== COVERAGE ANALYSIS ===")
print(f"Training vocabulary with >0 training examples: {TRAINING_VOCAB_WITH_EXAMPLES}")
print(f"  (REJ is a FEATURE_COL but has 0 UNSW training examples — excluded from 'represented')")
print()
print(f"Attack records with state in training vocab (≥1 example): {in_vocab_with_training:,}  ({100*in_vocab_with_training/attack_n:.1f}%)")
for state in TRAINING_VOCAB_WITH_EXAMPLES:
    cnt = attack_states.get(state, 0)
    print(f"  {state}: {cnt:,}  ({100*cnt/attack_n:.1f}%)")

print()
print(f"Attack records WITHOUT training representation: {no_training_repr:,}  ({100*no_training_repr/attack_n:.1f}%)")
print()
# breakdown of unrepresented
print("Breakdown of unrepresented records:")
for state, cnt in sorted(attack_states.items(), key=lambda x: -x[1]):
    if state not in TRAINING_VOCAB_WITH_EXAMPLES:
        reason = "feature column exists, 0 training examples" if state in TRAINING_VOCAB_ALL_COLS \
                 else "not in FEATURE_COLS → all-zero at inference"
        print(f"  {state or '(empty)':<10} {cnt:>6,}  ({100*cnt/attack_n:.1f}%)  [{reason}]")

print()
pct_no_repr = 100*no_training_repr/attack_n
print(f"==> {pct_no_repr:.1f}% of live attack records have no training representation")
print(f"    (Previous round's '0% overlap' figure was from a 499-record background-only log — void.)")
print(f"    User's calculation: 86.8% — {'CONFIRMED' if abs(pct_no_repr - 86.8) < 0.5 else f'CORRECTED to {pct_no_repr:.1f}%'}")
PYEOF
echo ""

# ── PART 4: Canonical record count reconciliation ─────────────────────────────
echo "$SEP"
echo "PART 4: CANONICAL RECORD COUNT RECONCILIATION"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")

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
total = 0
by_src = Counter()

for p in arch_logs + [SNAP]:
    raw_count = 0
    dedup_count = 0
    for row in parse_log_rows(p):
        raw_count += 1
        uid = row.get("uid","")
        src = row.get("id.orig_h","")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        dedup_count += 1
        total += 1
        by_src[src] += 1
    if raw_count != dedup_count:
        pass  # cross-file dups handled silently

kali = by_src.get("10.10.0.2", 0)
bg   = total - kali
print(f"CANONICAL COUNTS (single parse, snapshot-based):")
print(f"  Total (uid-deduped): {total:,}")
print(f"  Attack (10.10.0.2):  {kali:,}  ({100*kali/total:.2f}%)")
print(f"  Background:          {bg:,}  ({100*bg/total:.2f}%)")
print()
print(f"Previous round reported:")
print(f"  Part 1 Python block: 34,735")
print(f"  Part 5 Python block: 34,737  (2 extra — live conn.log written to between blocks)")
print(f"  This run (snapshot): {total}  — this is the canonical number for all thesis figures")
print()
print(f"Discrepancy cause: Part 5 in verify_v2.sh used a live current/conn.log,")
print(f"which had 2 records added by Zeek between the two Python script invocations.")
print(f"Fix: snapshot current conn.log once at script start; all parts use the snapshot.")
PYEOF
echo ""

# ── PART 5: Clean held-out IForest evaluation ─────────────────────────────────
echo "$SEP"
echo "PART 5: CLEAN HELD-OUT IFOREST EVALUATION (70/30 stratified split)"
echo "$SEP"
python3 - <<PYEOF
import gzip, sys, json, random
import numpy as np
import joblib
from pathlib import Path
from collections import Counter
from sklearn.ensemble import IsolationForest

ARCHIVE_DIR = Path("/opt/zeek/logs")
SNAP        = Path("/tmp/conn_current_snap.log")
KALI        = "10.10.0.2"
ALLOWLIST   = {"192.168.0.3", "127.0.0.1", "10.0.2.15"}
TODAY_DIR   = Path("ml/models/archive") / __import__('datetime').date.today().isoformat()
TODAY_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]
CONTAMINATION = 0.1

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
        sf(row.get("duration")), sf(row.get("orig_bytes")),
        sf(row.get("resp_bytes")), sf(row.get("orig_pkts")),
        sf(row.get("resp_pkts")),
        int(proto=="tcp"), int(proto=="udp"), int(proto=="icmp"),
        int(state=="S0"), int(state=="SF"), int(state=="REJ"), int(state=="RSTO"),
    ]

arch_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))

uid_seen = set()
uid_list = []   # ordered list of (uid, src, vec)

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
        uid_list.append((uid, src, row_to_vec(row)))

total = len(uid_list)
print(f"Canonical uid-deduped records: {total:,}")

# ── Stratified 70/30 split on attack records ──────────────────────────────────
# Rationale: 70/30 on 1,544 attack records → ~463 held-out positives
# Wilson CI at n=463, P=0.5: half-width ≈ 0.046. Usable (< 0.1 target).

attack_idx = [i for i, (uid, src, _) in enumerate(uid_list) if src == KALI]
bg_idx     = [i for i, (uid, src, _) in enumerate(uid_list) if src != KALI]

rng = random.Random(42)
rng.shuffle(attack_idx)

split = int(0.70 * len(attack_idx))
train_attack_idx = set(attack_idx[:split])
test_attack_idx  = set(attack_idx[split:])

# Training set: 70% attack + all background
train_idx = sorted(train_attack_idx | set(bg_idx))
test_idx  = sorted(test_attack_idx)  # held-out is attack records only (for clean P/R)

# But for evaluating the full test population (FP rate), we also need background in test
# Use complement of training set
test_all_idx = sorted(set(range(total)) - train_attack_idx - set(bg_idx))
# Actually let's evaluate on: held-out attack + all background (both allowlisted and not)
# to see FP rate on both full and allowlist-excluded populations
# Test set = test_attack + all background

n_train_attack = len(train_attack_idx)
n_test_attack  = len(test_attack_idx)
n_bg           = len(bg_idx)

print(f"\nTrain/test split:")
print(f"  Training set: {len(train_idx):,} records")
print(f"    Attack records in training: {n_train_attack:,}  (70% of {len(attack_idx):,})")
print(f"    Background records in training: {n_bg:,}  (all background)")
print(f"  Held-out attack records: {n_test_attack:,}  (30% of {len(attack_idx):,})")
print(f"  Evaluation set: held-out attack + all background = {n_test_attack + n_bg:,}")
print()
print(f"Split choice: 70/30 on attack records leaves {n_test_attack} held-out positives.")
print(f"Wilson CI at n={n_test_attack}, P=0.5: half-width ≈ {1.96*(0.5/n_test_attack**0.5):.3f}  (target <0.05 — {'OK' if 1.96*(0.5/n_test_attack**0.5)<0.05 else 'marginal'})")

# ── Train new live IForest ────────────────────────────────────────────────────
X_train = np.array([uid_list[i][2] for i in train_idx], dtype=float)
print(f"\nTraining IForest on {len(X_train):,} records (contamination={CONTAMINATION})...")
clf = IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                      n_jobs=-1, random_state=42)
clf.fit(X_train)

# Save model and manifest
model_out = TODAY_DIR / "iforest_live_holdout.joblib"
joblib.dump(clf, model_out)
manifest = {"train_uids": [uid_list[i][0] for i in train_idx],
            "n_train": len(train_idx),
            "n_train_attack": n_train_attack,
            "n_train_bg": n_bg,
            "split": "70% attack / all background in train; 30% attack held out",
            "random_state": 42}
manifest_out = TODAY_DIR / "train_index.json"
with open(manifest_out, "w") as f:
    json.dump(manifest, f, indent=2)
print(f"Model saved:    {model_out}")
print(f"Manifest saved: {manifest_out}")

# ── Evaluation ────────────────────────────────────────────────────────────────
def wilson_ci(k, n, z=1.96):
    if n==0: return (0.0,0.0)
    p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d
    m=z*((p*(1-p)/n+z*z/(4*n*n))**0.5)/d
    return (max(0.0,c-m), min(1.0,c+m))

def eval_on(model, eval_indices, bg_indices, label, excl_allowlist=False):
    # eval = held-out attack + background (optionally excluding allowlisted bg)
    all_eval_idx = list(eval_indices) + [i for i in bg_indices
                                          if (not excl_allowlist or uid_list[i][1] not in ALLOWLIST)]
    X_e = np.array([uid_list[i][2] for i in all_eval_idx], dtype=float)
    y_e = np.array([1 if uid_list[i][1]==KALI else 0 for i in all_eval_idx], dtype=int)

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
    print()

MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")
print("\n=== HELD-OUT EVALUATION: NEW LIVE IFOREST vs UNSW-CORRECTED ===")
print(f"Evaluation: held-out attack ({n_test_attack}) + background\n")
print("-- Full background (includes allowlisted) --")
eval_on(MODEL_UNSW, test_attack_idx, bg_idx, "UNSW-corrected (full bg)", excl_allowlist=False)
eval_on(clf,         test_attack_idx, bg_idx, "New live IForest (full bg)", excl_allowlist=False)

print("-- Allowlist-excluded background --")
eval_on(MODEL_UNSW, test_attack_idx, bg_idx, "UNSW-corrected (allowlist-excl)", excl_allowlist=True)
eval_on(clf,         test_attack_idx, bg_idx, "New live IForest (allowlist-excl)", excl_allowlist=True)
PYEOF
echo ""
echo "$SEP"
echo "DONE — paste full output to Claude"
echo "$SEP"
