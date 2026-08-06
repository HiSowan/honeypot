#!/usr/bin/env bash
# Stop the honeypot controller.

PID_FILE="/run/honeypot-controller.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No PID file found at $PID_FILE — controller may not be running."
    exit 0
fi

PID=$(cat "$PID_FILE")

if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    rm -f "$PID_FILE"
    echo "Controller stopped (PID $PID)."
else
    echo "Process $PID not found — removing stale PID file."
    rm -f "$PID_FILE"
fi
