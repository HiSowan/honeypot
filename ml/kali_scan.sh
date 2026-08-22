#!/bin/bash
# Run from Kali VM — Phase 1 vs Phase 2 nmap experiment
# Usage: bash kali_scan.sh scan1   (Phase 1 — before rotation)
#        bash kali_scan.sh scan2   (Phase 2 — after rotation)
#        bash kali_scan.sh trigger (aggressive scan to trigger threshold)

TARGET="10.10.0.1"
PORTS="21,22,23,25,80,443,445"
OUT_DIR="/tmp/honeypot_exp"
mkdir -p "$OUT_DIR"

case "$1" in
  scan1)
    echo "=== Phase 1 scan — recording baseline port set ==="
    sudo nmap -sS -p "$PORTS" "$TARGET" -oN "$OUT_DIR/kali_scan1.txt" -v
    echo ""
    echo "Open/closed ports:"
    grep -E "open|closed|filtered" "$OUT_DIR/kali_scan1.txt" | grep "tcp"
    ;;
  scan2)
    echo "=== Phase 2 scan — recording port set after rotation ==="
    sudo nmap -sS -p "$PORTS" "$TARGET" -oN "$OUT_DIR/kali_scan2.txt" -v
    echo ""
    echo "Open/closed ports:"
    grep -E "open|closed|filtered" "$OUT_DIR/kali_scan2.txt" | grep "tcp"
    echo ""
    echo "=== COMPARISON ==="
    echo "Phase 1 ports:"
    grep "tcp" "$OUT_DIR/kali_scan1.txt" | grep -E "open|closed|filtered"
    echo "Phase 2 ports:"
    grep "tcp" "$OUT_DIR/kali_scan2.txt" | grep -E "open|closed|filtered"
    ;;
  trigger)
    echo "=== Trigger scan — generates traffic to exceed scan threshold ==="
    echo "(SYN_SCAN_THRESHOLD=10, SCAN_PORT_THRESHOLD=5)"
    sudo nmap -sS -p 1-1024 "$TARGET" -v --min-rate 100
    echo ""
    echo "Threshold triggered. Wait 70 seconds for controller cycle, then run:"
    echo "  sudo python ml/eval_phase_compare.py --rotate --probed <ports-you-scanned>"
    ;;
  *)
    echo "Usage: $0 {scan1|scan2|trigger}"
    exit 1
    ;;
esac
