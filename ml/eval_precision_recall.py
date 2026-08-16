"""Ground-truth IForest precision/recall evaluation on live Zeek data.

Labels each conn.log connection by source IP:
  10.10.0.2  -> attack  (Kali VM, confirmed attacker)
  everything else -> background

Computes precision, recall, F1 for both IForest models at the -0.1
blocking threshold. Saves results to ml/eval_precision_recall.txt.

Usage (from ~/honeypot with venv active):
    python ml/eval_precision_recall.py
"""
import sys, warnings
from pathlib import Path

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

MODELS   = ROOT / "ml" / "models"
LIVE_LOG = Path("/opt/zeek/logs/current/conn.log")
OUT      = ROOT / "ml" / "eval_precision_recall.txt"

ATTACKER_IP   = "10.10.0.2"   # Kali VM — confirmed attack source
BLOCK_THRESH  = -0.1          # must match controller ML_BLOCK_THRESHOLD

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


# ── Parse conn.log — keep source IP for labelling ────────────────────────
sec("PARSING LIVE ZEEK CONN.LOG")

rows, src_ips = [], []
with open(LIVE_LOG) as f:
    for line in f:
        if line.startswith("#"):
            continue
        p = line.strip().split("\t")
        if len(p) < 20:
            continue
        try:
            src_ip = p[2]          # id.orig_h
            proto  = p[6].lower()
            state  = p[11].upper()
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
            }
            rows.append(row)
            src_ips.append(src_ip)
        except Exception:
            continue

X   = pd.DataFrame(rows, columns=FEATURE_COLS)
y_true = np.array([1 if ip == ATTACKER_IP else 0 for ip in src_ips])

out(f"Total records   : {len(X)}")
out(f"Attack  (label=1): {y_true.sum()}  [{ATTACKER_IP}]")
out(f"Background (label=0): {(y_true == 0).sum()}  [all other IPs]")

unique_ips = sorted(set(src_ips))
out(f"\nUnique source IPs observed:")
for ip in unique_ips:
    count = src_ips.count(ip)
    label = "ATTACK" if ip == ATTACKER_IP else "background"
    out(f"  {ip:<18} {count:>4} connections  [{label}]")


# ── Evaluate each IForest model ───────────────────────────────────────────
def evaluate_model(path, label, X, y_true, threshold):
    sec(f"ISOLATION FOREST — {label}")

    if not path.exists():
        out(f"Model not found: {path}")
        return

    model  = joblib.load(path)
    scores = model.decision_function(X)

    # Predicted attack = score below threshold
    y_pred = (scores < threshold).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())

    prec   = precision_score(y_true, y_pred, zero_division=0)
    rec    = recall_score(y_true, y_pred, zero_division=0)
    f1     = f1_score(y_true, y_pred, zero_division=0)

    out(f"Model file   : {path.name}")
    out(f"Threshold    : score < {threshold}")
    out()
    out(f"Flagged as attack : {y_pred.sum()} / {len(X)}")
    out()
    out("Confusion matrix (rows=actual, cols=predicted):")
    out(f"               Pred-Background  Pred-Attack")
    out(f"  Actual-Background   {tn:>5}          {fp:>5}")
    out(f"  Actual-Attack       {fn:>5}          {tp:>5}")
    out()
    out(f"True  Positives (TP) : {tp}  — attacker connections correctly flagged")
    out(f"False Positives (FP) : {fp}  — background connections wrongly flagged")
    out(f"False Negatives (FN) : {fn}  — attacker connections missed")
    out(f"True  Negatives (TN) : {tn}  — background connections correctly ignored")
    out()
    out(f"Precision : {prec:.3f}  (of flagged connections, how many are real attacks)")
    out(f"Recall    : {rec:.3f}  (of real attacks, how many were flagged)")
    out(f"F1-Score  : {f1:.3f}")
    out()
    out("Score distribution:")
    out(f"  mean  : {scores.mean():.4f}")
    out(f"  std   : {scores.std():.4f}")
    out(f"  min   : {scores.min():.4f}")
    out(f"  max   : {scores.max():.4f}")
    out(f"  median: {float(np.median(scores)):.4f}")
    out()

    # Per-IP breakdown
    out("Per-source-IP breakdown:")
    out(f"  {'IP':<18} {'True label':<12} {'Flagged':>7} {'Total':>7} {'Flag%':>7}")
    out(f"  {'-'*58}")
    for ip in sorted(set(src_ips)):
        idx   = np.array([i for i, s in enumerate(src_ips) if s == ip])
        n_tot = len(idx)
        n_flg = int(y_pred[idx].sum())
        lbl   = "attack" if ip == ATTACKER_IP else "background"
        out(f"  {ip:<18} {lbl:<12} {n_flg:>7} {n_tot:>7} {100*n_flg/n_tot:>6.1f}%")


evaluate_model(MODELS / "iforest_anomaly.joblib", "UNSW-NB15 baseline", X, y_true, BLOCK_THRESH)
evaluate_model(MODELS / "iforest_live.joblib",    "Live-retrained",     X, y_true, BLOCK_THRESH)


# ── Side-by-side summary ──────────────────────────────────────────────────
sec("SUMMARY — Both Models at Threshold -0.1")
out(f"{'Metric':<15} {'UNSW-NB15':>12} {'Live-retrained':>15}")
out(f"{'-'*45}")

for path, label in [
    (MODELS / "iforest_anomaly.joblib", "UNSW-NB15"),
    (MODELS / "iforest_live.joblib",    "Live"),
]:
    if not path.exists():
        continue
    m = joblib.load(path)
    s = m.decision_function(X)
    yp = (s < BLOCK_THRESH).astype(int)
    p = precision_score(y_true, yp, zero_division=0)
    r = recall_score(y_true, yp, zero_division=0)
    f = f1_score(y_true, yp, zero_division=0)
    tp = int(((yp==1)&(y_true==1)).sum())
    fp = int(((yp==1)&(y_true==0)).sum())
    fn = int(((yp==0)&(y_true==1)).sum())
    if label == "UNSW-NB15":
        row_p, row_r, row_f = f"{p:.3f}", f"{r:.3f}", f"{f:.3f}"
        row_tp, row_fp, row_fn = tp, fp, fn
        row_flg = int(yp.sum())
    else:
        out(f"{'Flagged':<15} {row_flg:>12} {int(yp.sum()):>15}")
        out(f"{'TP':<15} {row_tp:>12} {tp:>15}")
        out(f"{'FP':<15} {row_fp:>12} {fp:>15}")
        out(f"{'FN':<15} {row_fn:>12} {fn:>15}")
        out(f"{'Precision':<15} {row_p:>12} {p:>15.3f}")
        out(f"{'Recall':<15} {row_r:>12} {r:>15.3f}")
        out(f"{'F1':<15} {row_f:>12} {f:>15.3f}")

OUT.write_text("\n".join(lines), encoding="utf-8")
sec(f"DONE — saved to {OUT}")
