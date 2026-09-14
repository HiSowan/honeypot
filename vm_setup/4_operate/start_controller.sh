#!/usr/bin/env bash
# Start the honeypot controller in the background.
# Logs go to /var/log/honeypot/controller.log
# Usage: sudo bash scripts/start_controller.sh [--live] [--ml-live]
#
# --live     enables live firewall rules (FIREWALL_LIVE=1)
# --ml-live  enables live ML blocking (ML_LIVE=1); shadow mode only if omitted
# Omit both for fully dry-run mode (default, safe during build phase).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO_DIR/venv"
LOG_DIR="/var/log/honeypot"
LOG_FILE="$LOG_DIR/controller.log"
PID_FILE="/run/honeypot-controller.pid"

if [ ! -x "$VENV/bin/python3" ]; then
    echo "ERROR: venv not found at $VENV — run: python3 -m venv venv && venv/bin/pip install -r requirements.txt"
    exit 1
fi

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Controller already running (PID $(cat "$PID_FILE")). Stop it first with scripts/stop_controller.sh"
    exit 1
fi

mkdir -p "$LOG_DIR"

FIREWALL_LIVE=0
ML_LIVE=0
for arg in "$@"; do
    case "$arg" in
        --live)    FIREWALL_LIVE=1 ;;
        --ml-live) ML_LIVE=1 ;;
    esac
done

echo "Starting honeypot controller (FIREWALL_LIVE=$FIREWALL_LIVE, ML_LIVE=$ML_LIVE)..."
echo "Logging to $LOG_FILE"

FIREWALL_LIVE=$FIREWALL_LIVE ML_LIVE=$ML_LIVE \
    nohup "$VENV/bin/python3" -m controller.main \
    >> "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"
echo "Controller started (PID $!)."
