#!/usr/bin/env bash
# Parts 1, 2, 3 (diagnostics), 5, 6 verification script — v2
# Part 4 (mapping test) is handled separately from the code.
#
# Run from ~/honeypot with venv active:
#
#   cd ~/honeypot
#   git pull
#   source venv/bin/activate
#   bash scripts/verify_v2.sh 2>&1 | tee /tmp/verify_v2_output.txt
#
# Then: cat /tmp/verify_v2_output.txt   (paste full output to Claude)

set -euo pipefail
SEP="========================================"
ARCHIVE_DIR="/opt/zeek/logs"
MODELS="ml/models"
TODAY=$(date +%Y-%m-%d)

# ── Backup all .joblib models before anything else ────────────────────────────
echo "$SEP"
echo "PRECAUTION: Backing up .joblib files to $MODELS/archive/$TODAY/"
echo "$SEP"
mkdir -p "$MODELS/archive/$TODAY"
for f in "$MODELS"/*.joblib; do
    [ -f "$f" ] && cp -p "$f" "$MODELS/archive/$TODAY/" && echo "  backed up: $(basename $f)"
done
echo ""

# ── PART 1: Dedup collision analysis ──────────────────────────────────────────
echo "$SEP"
echo "PART 1: DEDUP COLLISION ANALYSIS — raw vs uid-deduped populations"
echo "$SEP"
python3 - <<'PYEOF'
import gzip, os, sys
from pathlib import Path
from collections import Counter, defaultdict

ARCHIVE_DIR = Path("/opt/zeek/logs")

# Skip conn-summary files (they load 0 records and have different formats)
def is_conn_log(p: Path) -> bool:
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path: Path) -> list[dict]:
    """Parse a Zeek conn.log or conn.log.gz into dicts using #fields header."""
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
                parts = line.split("\t")
                row = dict(zip(fields, parts))
                rows.append(row)
    except Exception as e:
        print(f"  Warning: {path.name}: {e}", file=sys.stderr)
    return rows

all_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))
current = ARCHIVE_DIR / "current" / "conn.log"

print(f"Archive log files (excluding current): {len(all_logs)}")
print()

# ── Step 1: raw count (no dedup) ──────────────────────────────────────────────
raw_total = 0
raw_by_src = Counter()
ts_srcip_keys = set()
ts_srcip_collisions_by_src = Counter()

for p in all_logs:
    rows = parse_log_rows(p)
    for row in rows:
        src = row.get("id.orig_h", "")
        ts  = row.get("ts", "")
        raw_total += 1
        raw_by_src[src] += 1
        key = (ts, src)
        if key in ts_srcip_keys:
            ts_srcip_collisions_by_src[src] += 1
        ts_srcip_keys.add(key)

# Also add current log
if current.exists():
    rows = parse_log_rows(current)
    for row in rows:
        src = row.get("id.orig_h", "")
        ts  = row.get("ts", "")
        raw_total += 1
        raw_by_src[src] += 1
        key = (ts, src)
        if key in ts_srcip_keys:
            ts_srcip_collisions_by_src[src] += 1
        ts_srcip_keys.add(key)

raw_attack = raw_by_src.get("10.10.0.2", 0)
raw_bg = raw_total - raw_attack

print("=== RAW (no dedup) ===")
print(f"Total records:              {raw_total:>8,}")
print(f"Attack (10.10.0.2):         {raw_attack:>8,}  ({100*raw_attack/raw_total:.2f}%)")
print(f"Background (all others):    {raw_bg:>8,}  ({100*raw_bg/raw_total:.2f}%)")
print()
print("Top 10 source IPs (raw):")
for ip, cnt in raw_by_src.most_common(10):
    print(f"  {ip:<45} {cnt:>7,}")
print()

print("=== (ts, src_ip) COLLISION ANALYSIS ===")
total_collisions = sum(ts_srcip_collisions_by_src.values())
print(f"Total (ts, src_ip) collisions: {total_collisions:,}")
print("Collisions by src_ip:")
for ip, cnt in ts_srcip_collisions_by_src.most_common(15):
    pct_of_raw = 100*cnt / raw_by_src.get(ip, 1)
    print(f"  {ip:<45} {cnt:>7,}  ({pct_of_raw:.1f}% of that IP's raw records)")
print()

# ── Step 2: uid-based dedup ───────────────────────────────────────────────────
uid_seen = set()
uid_dedup_total = 0
uid_dedup_by_src = Counter()
uid_empty_count = 0

for p in all_logs:
    rows = parse_log_rows(p)
    for row in rows:
        uid = row.get("uid", "")
        src = row.get("id.orig_h", "")
        if not uid:
            uid_empty_count += 1
            # fall back to 5-tuple + ts
            uid = "\t".join([
                row.get("ts",""), src,
                row.get("id.orig_p",""), row.get("id.resp_h",""),
                row.get("id.resp_p",""), row.get("proto",""),
            ])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        uid_dedup_total += 1
        uid_dedup_by_src[src] += 1

if current.exists():
    rows = parse_log_rows(current)
    for row in rows:
        uid = row.get("uid", "")
        src = row.get("id.orig_h", "")
        if not uid:
            uid_empty_count += 1
            uid = "\t".join([
                row.get("ts",""), src,
                row.get("id.orig_p",""), row.get("id.resp_h",""),
                row.get("id.resp_p",""), row.get("proto",""),
            ])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        uid_dedup_total += 1
        uid_dedup_by_src[src] += 1

uid_attack = uid_dedup_by_src.get("10.10.0.2", 0)
uid_bg = uid_dedup_total - uid_attack

print("=== UID-DEDUPED ===")
print(f"Records with empty uid (used 5-tuple fallback): {uid_empty_count:,}")
print(f"Total records after uid dedup:                  {uid_dedup_total:>8,}")
print(f"Attack (10.10.0.2):                             {uid_attack:>8,}  ({100*uid_attack/uid_dedup_total:.2f}%)")
print(f"Background (all others):                        {uid_bg:>8,}  ({100*uid_bg/uid_dedup_total:.2f}%)")
print()
print("Top 10 source IPs (uid-deduped):")
for ip, cnt in uid_dedup_by_src.most_common(10):
    print(f"  {ip:<45} {cnt:>7,}")
print()

# ── Step 3: reconciliation with thesis Table 5.2 ──────────────────────────────
print("=== RECONCILIATION ===")
print("Previous Part 5 raw:     34,133 total → 291 attack (0.95%)  [WRONG: (ts,src_ip) dedup]")
print(f"Corrected uid-dedup:    {uid_dedup_total:>6,} total → {uid_attack} attack ({100*uid_attack/uid_dedup_total:.2f}%)")
print()
print("What Table 5.2 should say:")
print(f"  Archive total (uid-dedup): {uid_dedup_total:,}")
print(f"  Attack records:            {uid_attack:,}")
print(f"  Background records:        {uid_bg:,}")
print(f"  Attack base rate:          {100*uid_attack/uid_dedup_total:.2f}%")
PYEOF
echo ""

# ── PART 2: conn_state distribution on attack vs background records ───────────
echo "$SEP"
echo "PART 2: conn_state DISTRIBUTION — archive attack vs background records"
echo "$SEP"
python3 - <<'PYEOF'
import gzip, sys
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
KALI = "10.10.0.2"

def is_conn_log(p: Path) -> bool:
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path: Path) -> list[dict]:
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
                parts = line.split("\t")
                row = dict(zip(fields, parts))
                rows.append(row)
    except Exception as e:
        print(f"  Warning: {path.name}: {e}", file=sys.stderr)
    return rows

all_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))
current = ARCHIVE_DIR / "current" / "conn.log"

# uid-dedup pass
uid_seen = set()
attack_states = Counter()
bg_states = Counter()
attack_n = 0
bg_n = 0

for p in list(all_logs) + ([current] if current.exists() else []):
    rows = parse_log_rows(p)
    for row in rows:
        uid = row.get("uid", "")
        src = row.get("id.orig_h", "")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        state = row.get("conn_state", "").strip()
        if src == KALI:
            attack_states[state] += 1
            attack_n += 1
        else:
            bg_states[state] += 1
            bg_n += 1

print(f"ATTACK records (10.10.0.2): {attack_n:,}")
if attack_n:
    print("conn_state distribution:")
    for state, cnt in sorted(attack_states.items(), key=lambda x: -x[1]):
        print(f"  {state or '(empty)':<12}  {cnt:>6,}  ({100*cnt/attack_n:.1f}%)")
    s0_pct = 100 * attack_states.get("S0", 0) / attack_n
    print(f"\n  S0 (SYN, no reply — expected for nmap SYN scan): {attack_states.get('S0',0):,}  ({s0_pct:.1f}%)")
else:
    print("  NO ATTACK RECORDS FOUND")

print()
print(f"BACKGROUND records (all others): {bg_n:,}")
if bg_n:
    print("conn_state distribution (top 10):")
    for state, cnt in sorted(bg_states.items(), key=lambda x: -x[1])[:10]:
        print(f"  {state or '(empty)':<12}  {cnt:>6,}  ({100*cnt/bg_n:.1f}%)")

print()
# The thesis claim in §5.2.1 and §6.4.1
if attack_n:
    s0_count = attack_states.get("S0", 0)
    if s0_count > attack_n * 0.5:
        print("VERDICT: Attack records are S0-DOMINANT.")
        print("  The 499-record current log was a broken capture (no attacker traffic in that session).")
        print("  The thesis claim that Zeek records 'correctly populate conn_state_S0=1 for nmap SYN-only connections' STANDS for the archive data.")
    else:
        oth_count = attack_states.get("OTH", 0) + attack_states.get("RSTRH", 0) + attack_states.get("SHR", 0)
        print("VERDICT: Attack records are NOT S0-dominant.")
        print(f"  Originator-blind states (OTH+RSTRH+SHR) = {oth_count}/{attack_n} ({100*oth_count/attack_n:.1f}%)")
        print("  This indicates a Zeek capture defect — Zeek is not seeing the originator direction.")
        print("  Proceed to Part 3 for capture diagnosis.")
        print("  The thesis text claiming conn_state_S0 for nmap SYN traffic is INCORRECT.")
PYEOF
echo ""

# ── PART 3: Zeek capture diagnostics ──────────────────────────────────────────
echo "$SEP"
echo "PART 3: ZEEK CAPTURE DIAGNOSTICS"
echo "$SEP"

echo "--- Zeek interface binding ---"
echo "node.cfg:"
cat /opt/zeek/etc/node.cfg 2>/dev/null || echo "  /opt/zeek/etc/node.cfg not found"
echo ""

echo "local.zeek (checksum-related lines):"
grep -i "checksum\|ignore_check\|interface" /opt/zeek/share/zeek/site/local.zeek 2>/dev/null || echo "  No checksum/interface lines found"
echo ""

echo "--- Checksum offloading (ethtool) ---"
echo "ethtool -k enp0s3 | grep checksum:"
ethtool -k enp0s3 2>/dev/null | grep -i checksum || echo "  ethtool not available or interface not found"
echo ""

echo "--- Current Zeek process / interface ---"
ps aux | grep -i "[z]eek" | head -5 || echo "  No zeek process found"
echo ""

echo "--- Zeek systemd unit interface ---"
grep -r "interface\|enp0s3" /etc/systemd/system/ 2>/dev/null | head -10 || echo "  No systemd unit matches"
systemctl cat zeek 2>/dev/null | grep -i "interface\|enp0s3" || echo "  zeekctl systemd unit: not found or no interface config"
echo ""

# ── PART 5: Ground-truth P/R with uid dedup ───────────────────────────────────
echo "$SEP"
echo "PART 5: GROUND-TRUTH P/R — uid-deduped archive, both IForest models"
echo "$SEP"
python3 - <<'PYEOF'
import gzip, sys
import numpy as np
import joblib
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
KALI = "10.10.0.2"

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")
MODEL_LIVE = joblib.load("ml/models/iforest_live.joblib")
MODEL_RF   = joblib.load("ml/models/rf_attack_type.joblib")

def is_conn_log(p: Path) -> bool:
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path: Path) -> list[dict]:
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
                parts = line.split("\t")
                row = dict(zip(fields, parts))
                rows.append(row)
    except Exception as e:
        print(f"  Warning: {path.name}: {e}", file=sys.stderr)
    return rows

def row_to_features(row: dict) -> dict:
    proto = row.get("proto", "").lower()
    state = row.get("conn_state", "").upper()
    def safe_float(v):
        try: return float(v) if v and v != "-" else 0.0
        except: return 0.0
    return {
        "duration":        safe_float(row.get("duration")),
        "orig_bytes":      safe_float(row.get("orig_bytes")),
        "resp_bytes":      safe_float(row.get("resp_bytes")),
        "orig_pkts":       safe_float(row.get("orig_pkts")),
        "resp_pkts":       safe_float(row.get("resp_pkts")),
        "proto_tcp":       int(proto == "tcp"),
        "proto_udp":       int(proto == "udp"),
        "proto_icmp":      int(proto == "icmp"),
        "conn_state_S0":   int(state == "S0"),
        "conn_state_SF":   int(state == "SF"),
        "conn_state_REJ":  int(state == "REJ"),
        "conn_state_RSTO": int(state == "RSTO"),
    }

all_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))
current = ARCHIVE_DIR / "current" / "conn.log"

uid_seen = set()
X_rows = []
y_rows = []

for p in list(all_logs) + ([current] if current.exists() else []):
    rows = parse_log_rows(p)
    for row in rows:
        uid = row.get("uid", "")
        src = row.get("id.orig_h", "")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        X_rows.append([row_to_features(row)[f] for f in FEATURE_COLS])
        y_rows.append(1 if src == KALI else 0)

X = np.array(X_rows, dtype=float)
y = np.array(y_rows, dtype=int)
n = len(X)
n_pos = y.sum()
n_neg = n - n_pos
base_rate = 100 * n_pos / n if n > 0 else 0

print(f"Dataset (uid-deduped): {n:,} records")
print(f"  Attack  (10.10.0.2): {n_pos:,}  ({base_rate:.2f}%)")
print(f"  Background:          {n_neg:,}  ({100-base_rate:.2f}%)")
print()

def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    margin = z * ((p*(1-p)/n + z**2/(4*n**2))**0.5) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))

def eval_iforest(model, X, y, label, threshold=-0.1):
    scores = model.decision_function(X)
    flags  = (scores < threshold).astype(int)
    TP = int(((flags==1) & (y==1)).sum())
    FP = int(((flags==1) & (y==0)).sum())
    TN = int(((flags==0) & (y==0)).sum())
    FN = int(((flags==0) & (y==1)).sum())
    P  = TP/(TP+FP) if (TP+FP) else 0.0
    R  = TP/(TP+FN) if (TP+FN) else 0.0
    F1 = 2*P*R/(P+R) if (P+R) else 0.0
    P_ci = wilson_ci(TP, TP+FP)
    R_ci = wilson_ci(TP, TP+FN)
    print(f"  {label}")
    print(f"    TP={TP}  FP={FP}  TN={TN}  FN={FN}")
    print(f"    Precision: {P:.3f}  [95% CI: {P_ci[0]:.3f}–{P_ci[1]:.3f}]  (denominator n={TP+FP})")
    print(f"    Recall:    {R:.3f}  [95% CI: {R_ci[0]:.3f}–{R_ci[1]:.3f}]  (denominator n={TP+FN}={n_pos})")
    print(f"    F1:        {F1:.3f}")
    print(f"    Flag rate: {TP+FP}/{n} ({100*(TP+FP)/n:.2f}%)")
    print()

print(f"=== IForest evaluation (threshold=-0.1, base rate={base_rate:.2f}%) ===")
eval_iforest(MODEL_UNSW, X, y, "UNSW-corrected IForest")
eval_iforest(MODEL_LIVE, X, y, "Live-retrained IForest")

print("=== RF attack-type distribution (uid-deduped) ===")
rf_preds = MODEL_RF.predict(X)
cnt = Counter(rf_preds)
total = len(rf_preds)
for cls, n_cls in sorted(cnt.items(), key=lambda x: -x[1]):
    print(f"  {cls:<22} {n_cls:>7,}  ({100*n_cls/total:.2f}%)")

rf_attack_pred = total - cnt.get("Normal", 0)
actual_attack = n_pos
print()
print(f"RF records classified as non-Normal: {rf_attack_pred:,}")
print(f"Actual attack records:               {actual_attack:,}")
if actual_attack > 0:
    print(f"RF sensitivity on attack class:      {100*rf_attack_pred/actual_attack:.1f}% (upper bound — assumes all non-Normal are TP)")
PYEOF
echo ""

# ── PART 6: Held-out IForest evaluation ───────────────────────────────────────
echo "$SEP"
echo "PART 6: IDENTIFY IFOREST_LIVE TRAINING RECORDS + HELD-OUT EVALUATION"
echo "$SEP"

echo "--- Shell history check ---"
echo "Looking for train_iforest_live in history:"
grep -a "iforest_live\|train_iforest_live" ~/.bash_history 2>/dev/null || echo "  Not found in ~/.bash_history"
echo ""

# Model training timestamp
python3 - <<'PYEOF'
import os, gzip, sys
import numpy as np
import joblib
from pathlib import Path
from collections import Counter

ARCHIVE_DIR = Path("/opt/zeek/logs")
KALI = "10.10.0.2"
MODEL_LIVE_PATH = Path("ml/models/iforest_live.joblib")
MODEL_LIVE = joblib.load(str(MODEL_LIVE_PATH))
MODEL_UNSW = joblib.load("ml/models/iforest_anomaly.joblib")

model_mtime = os.stat(MODEL_LIVE_PATH).st_mtime
from datetime import datetime, timezone
model_dt = datetime.fromtimestamp(model_mtime, tz=timezone.utc)
print(f"iforest_live.joblib mtime: {model_dt.isoformat()}")
print(f"  unix ts: {model_mtime:.0f}")
print()

FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

def is_conn_log(p: Path) -> bool:
    n = p.name
    return "conn." in n and "conn-summary" not in n

def parse_log_rows(path: Path) -> list[dict]:
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
                parts = line.split("\t")
                row = dict(zip(fields, parts))
                rows.append(row)
    except Exception as e:
        print(f"  Warning: {path.name}: {e}", file=sys.stderr)
    return rows

def row_to_features(row: dict) -> dict:
    proto = row.get("proto", "").lower()
    state = row.get("conn_state", "").upper()
    def safe_float(v):
        try: return float(v) if v and v != "-" else 0.0
        except: return 0.0
    return {
        "duration":        safe_float(row.get("duration")),
        "orig_bytes":      safe_float(row.get("orig_bytes")),
        "resp_bytes":      safe_float(row.get("resp_bytes")),
        "orig_pkts":       safe_float(row.get("orig_pkts")),
        "resp_pkts":       safe_float(row.get("resp_pkts")),
        "proto_tcp":       int(proto == "tcp"),
        "proto_udp":       int(proto == "udp"),
        "proto_icmp":      int(proto == "icmp"),
        "conn_state_S0":   int(state == "S0"),
        "conn_state_SF":   int(state == "SF"),
        "conn_state_REJ":  int(state == "REJ"),
        "conn_state_RSTO": int(state == "RSTO"),
    }

# --- Strategy: training records = uid-deduped records with ts < model_mtime ---
# This uses ALL archive records before the model was trained.
# Note: iforest_live was trained on ONE log file passed as argument.
# We don't know exactly which file. Using ts < model_mtime is the best
# proxy we have without shell history.

all_logs = sorted(p for p in ARCHIVE_DIR.rglob("*.log*") if is_conn_log(p) and "current" not in str(p))
current = ARCHIVE_DIR / "current" / "conn.log"

uid_seen = set()
train_rows = []   # ts < model mtime
held_out_rows = []   # ts >= model mtime

for p in list(all_logs) + ([current] if current.exists() else []):
    rows = parse_log_rows(p)
    for row in rows:
        uid = row.get("uid", "")
        src = row.get("id.orig_h", "")
        if not uid:
            uid = "\t".join([row.get("ts",""), src, row.get("id.orig_p",""),
                             row.get("id.resp_h",""), row.get("id.resp_p",""), row.get("proto","")])
        if uid in uid_seen:
            continue
        uid_seen.add(uid)
        try:
            ts = float(row.get("ts", 0))
        except:
            ts = 0.0
        feat = [row_to_features(row)[f] for f in FEATURE_COLS]
        gt = 1 if src == KALI else 0
        entry = (feat, gt, src)
        if ts < model_mtime:
            train_rows.append(entry)
        else:
            held_out_rows.append(entry)

n_train = len(train_rows)
n_train_attack = sum(1 for _, gt, _ in train_rows if gt == 1)
n_train_bg = n_train - n_train_attack
n_ho = len(held_out_rows)
n_ho_attack = sum(1 for _, gt, _ in held_out_rows if gt == 1)
n_ho_bg = n_ho - n_ho_attack

print("=== TRAINING BOUNDARY SPLIT (ts < model_mtime) ===")
print(f"Records with ts < {model_dt.isoformat()} (training window):")
print(f"  Total:   {n_train:,}")
print(f"  Attack:  {n_train_attack:,}  ({100*n_train_attack/n_train:.2f}% of train window)" if n_train else "  (none)")
print(f"  Background: {n_train_bg:,}")
print()
print(f"Records with ts >= model_mtime (held-out):")
print(f"  Total:   {n_ho:,}")
print(f"  Attack:  {n_ho_attack:,}  ({100*n_ho_attack/n_ho:.2f}% of held-out)" if n_ho else "  (none)")
print(f"  Background: {n_ho_bg:,}")
print()

# --- Held-out evaluation if there are positives ---
if n_ho_attack == 0:
    print("WARNING: No attack records in held-out set (all 10.10.0.2 records pre-date the model).")
    print("Out-of-sample evaluation with ground-truth positives is not possible with this split.")
    print()
    print("Falling back: evaluating both models on TRAIN WINDOW records (in-sample for live model only).")
    eval_set = train_rows
    eval_label = "TRAIN WINDOW (in-sample — lower-bound measure)"
else:
    eval_set = held_out_rows
    eval_label = "HELD-OUT SET (out-of-sample)"

print(f"=== EVALUATION ON {eval_label} ===")
if not eval_set:
    print("  No records available for evaluation.")
else:
    X_e = np.array([r[0] for r in eval_set], dtype=float)
    y_e = np.array([r[1] for r in eval_set], dtype=int)
    n_e = len(X_e)
    n_pos_e = y_e.sum()
    base_e = 100 * n_pos_e / n_e if n_e else 0

    print(f"Records: {n_e:,},  Attack: {n_pos_e:,} ({base_e:.2f}%),  Background: {n_e-n_pos_e:,}")
    print()

    def wilson_ci(k, n, z=1.96):
        if n == 0: return (0.0, 0.0)
        p = k / n
        denom = 1 + z**2 / n
        center = (p + z**2 / (2*n)) / denom
        margin = z * ((p*(1-p)/n + z**2/(4*n**2))**0.5) / denom
        return (max(0.0, center-margin), min(1.0, center+margin))

    for model, mname in [(MODEL_UNSW, "UNSW-corrected"), (MODEL_LIVE, "Live-retrained")]:
        scores = model.decision_function(X_e)
        flags  = (scores < -0.1).astype(int)
        TP = int(((flags==1) & (y_e==1)).sum())
        FP = int(((flags==1) & (y_e==0)).sum())
        TN = int(((flags==0) & (y_e==0)).sum())
        FN = int(((flags==0) & (y_e==1)).sum())
        P  = TP/(TP+FP) if (TP+FP) else 0.0
        R  = TP/(TP+FN) if (TP+FN) else 0.0
        F1 = 2*P*R/(P+R) if (P+R) else 0.0
        P_ci = wilson_ci(TP, TP+FP)
        R_ci = wilson_ci(TP, TP+FN)
        print(f"  {mname}")
        print(f"    TP={TP}  FP={FP}  TN={TN}  FN={FN}")
        print(f"    Precision: {P:.3f}  [95% CI: {P_ci[0]:.3f}–{P_ci[1]:.3f}]  (n={TP+FP})")
        print(f"    Recall:    {R:.3f}  [95% CI: {R_ci[0]:.3f}–{R_ci[1]:.3f}]  (n={TP+FN})")
        print(f"    F1:        {F1:.3f}")
        print(f"    Flag rate: {TP+FP}/{n_e} ({100*(TP+FP)/n_e:.2f}%)")
        print()
PYEOF
echo ""
echo "$SEP"
echo "DONE — paste full output to Claude"
echo "$SEP"
