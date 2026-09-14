#!/usr/bin/env bash
# Switch the controller's operating phase at runtime.
# Usage: sudo bash scripts/set_phase.sh <static|adaptive|adaptive_ml>
#
# The controller reads phase.conf on every poll tick, so no restart needed.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PHASE_CONF="$REPO_DIR/config/phase.conf"
VALID_PHASES="static adaptive adaptive_ml"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <static|adaptive|adaptive_ml>"
    exit 1
fi

PHASE="$1"

if ! echo "$VALID_PHASES" | grep -qw "$PHASE"; then
    echo "ERROR: Unknown phase '$PHASE'. Valid values: $VALID_PHASES"
    exit 1
fi

# Warn before enabling live ML blocking
if [ "$PHASE" = "adaptive_ml" ]; then
    echo "NOTE: adaptive_ml enables ML scoring. Live blocking requires ML_LIVE=1 when starting the controller."
    echo "      By default, flagged IPs are only logged (shadow mode)."
fi

echo "phase=$PHASE" > "$PHASE_CONF"
echo "Phase set to '$PHASE'. Controller will apply on next poll tick."
