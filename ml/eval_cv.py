"""5-fold stratified cross-validation for the Random Forest on UNSW-NB15.

Confirms the 0.81 weighted accuracy is stable across folds and not a
lucky single train/test split. Saves results to ml/eval_cv.txt.

Usage (from ~/honeypot with venv active):
    python ml/eval_cv.py
"""
import sys, warnings, time
from pathlib import Path

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import make_scorer, f1_score

UNSW_CSV = ROOT / "data" / "raw" / "UNSW_NB15_training-set.CSV"
OUT      = ROOT / "ml" / "eval_cv.txt"

ATTACK_CATS = [
    "Normal", "Fuzzers", "Analysis", "Backdoors", "DoS",
    "Exploits", "Generic", "Reconnaissance", "Shellcode", "Worms",
]
FEATURE_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ", "conn_state_RSTO",
]

lines = []

def out(s=""):
    print(s)
    lines.append(str(s))

def sec(title):
    bar = "=" * 65
    out(); out(bar); out(title); out(bar)


sec("5-FOLD STRATIFIED CROSS-VALIDATION — Random Forest (UNSW-NB15)")

# ── Load and preprocess dataset ───────────────────────────────────────────
out("Loading dataset...")
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

out(f"Dataset  : {len(X):,} records, {X.shape[1]} features")
out(f"Classes  : {sorted(y.unique())}")
out()

# ── Define model — same hyperparameters as train_rf.py ────────────────────
rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)

# ── Define scorers ────────────────────────────────────────────────────────
scoring = {
    "accuracy":      "accuracy",
    "weighted_f1":   make_scorer(f1_score, average="weighted", zero_division=0),
    "macro_f1":      make_scorer(f1_score, average="macro",    zero_division=0),
}

# ── Run 5-fold stratified CV ──────────────────────────────────────────────
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

out("Running 5-fold stratified cross-validation (this takes a few minutes)...")
t0 = time.time()

results = cross_validate(rf, X, y, cv=cv, scoring=scoring,
                         return_train_score=False, n_jobs=1)

elapsed = time.time() - t0
out(f"Completed in {elapsed:.0f}s")
out()

# ── Per-fold results ──────────────────────────────────────────────────────
sec("Per-Fold Results")
out(f"{'Fold':<6} {'Accuracy':>10} {'Weighted F1':>12} {'Macro F1':>10}")
out(f"{'-'*42}")
for i in range(5):
    out(f"  {i+1:<4} "
        f"{results['test_accuracy'][i]:>10.4f} "
        f"{results['test_weighted_f1'][i]:>12.4f} "
        f"{results['test_macro_f1'][i]:>10.4f}")

# ── Summary statistics ────────────────────────────────────────────────────
sec("Summary — Mean ± Std Across 5 Folds")

acc  = results["test_accuracy"]
wf1  = results["test_weighted_f1"]
mf1  = results["test_macro_f1"]

out(f"{'Metric':<20} {'Mean':>8} {'Std':>8} {'Min':>8} {'Max':>8}")
out(f"{'-'*52}")
out(f"{'Accuracy':<20} {acc.mean():>8.4f} {acc.std():>8.4f} {acc.min():>8.4f} {acc.max():>8.4f}")
out(f"{'Weighted F1':<20} {wf1.mean():>8.4f} {wf1.std():>8.4f} {wf1.min():>8.4f} {wf1.max():>8.4f}")
out(f"{'Macro F1':<20} {mf1.mean():>8.4f} {mf1.std():>8.4f} {mf1.min():>8.4f} {mf1.max():>8.4f}")

out()
out("Comparison with single 80/20 split (from eval_ch5.py):")
out(f"  Single split accuracy   : 0.8100")
out(f"  5-fold mean accuracy    : {acc.mean():.4f}  (diff: {acc.mean()-0.81:+.4f})")
out(f"  Single split weighted F1: 0.7900")
out(f"  5-fold mean weighted F1 : {wf1.mean():.4f}  (diff: {wf1.mean()-0.79:+.4f})")
out(f"  Single split macro F1   : 0.5900")
out(f"  5-fold mean macro F1    : {mf1.mean():.4f}  (diff: {mf1.mean()-0.59:+.4f})")
out()

if acc.std() < 0.01:
    out("Verdict: LOW variance across folds (std < 0.01) — single-split result is STABLE.")
elif acc.std() < 0.02:
    out("Verdict: MODERATE variance across folds (std < 0.02) — single-split result is representative.")
else:
    out(f"Verdict: HIGHER variance across folds (std={acc.std():.4f}) — "
        "single-split result may be optimistic.")

OUT.write_text("\n".join(lines), encoding="utf-8")
sec(f"DONE — saved to {OUT}")
