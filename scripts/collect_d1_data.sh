#!/usr/bin/env bash
# Collect all data needed for thesis D1 placeholders.
# Run on the Ubuntu VM: bash scripts/collect_d1_data.sh
# Paste the entire output back to Claude.

set -euo pipefail

SEP="========================================"

echo "$SEP"
echo "SECTION: VERSION NUMBERS"
echo "$SEP"
echo "scikit-learn: $(pip show scikit-learn 2>/dev/null | grep '^Version' | awk '{print $2}')"
echo "promtail:     $(promtail --version 2>&1 | head -1)"
echo "iptables-persistent: $(dpkg -l iptables-persistent 2>/dev/null | awk '/^ii/{print $3}' || echo 'NOT INSTALLED')"

echo ""
echo "$SEP"
echo "SECTION: SHADOW_MODE.CSV"
echo "$SEP"

SHADOW=/var/log/honeypot/shadow_mode.csv

if [[ ! -f "$SHADOW" ]]; then
    echo "FILE NOT FOUND: $SHADOW"
    exit 0
fi

echo "Total rows (excluding header): $(tail -n +2 "$SHADOW" | wc -l)"
echo ""
echo "Per-IP breakdown (would_block=True rows only):"
awk -F',' 'NR>1 && $8=="True" {print $2}' "$SHADOW" \
    | sort | uniq -c | sort -rn \
    | awk '{printf "  %-18s %s would-block entries\n", $2, $1}'

echo ""
echo "Per-IP breakdown (all logged rows):"
awk -F',' 'NR>1 {print $2}' "$SHADOW" \
    | sort | uniq -c | sort -rn \
    | awk '{printf "  %-18s %s total rows\n", $2, $1}'

echo ""
echo "Full CSV contents:"
cat "$SHADOW"
