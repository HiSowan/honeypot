#!/usr/bin/env bash
COWRIE_DIR=/home/cowrie/cowrie
PID_FILE=$COWRIE_DIR/var/run/cowrie.pid
if [ -f "$PID_FILE" ]; then
  sudo kill "$(cat $PID_FILE)" && echo "Cowrie stopped."
else
  echo "No PID file found — Cowrie may not be running."
fi
