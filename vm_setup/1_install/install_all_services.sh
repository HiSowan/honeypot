#!/usr/bin/env bash
# Install all honeypot components as systemd services.
# After this, everything starts automatically on boot.
#
# Usage: sudo bash scripts/install_all_services.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO_DIR/scripts"
SYSTEMD="/etc/systemd/system"

echo "Installing honeypot systemd services..."

# Copy all service files
for svc in zeek cowrie loki promtail honeypot-controller; do
    cp "$SCRIPTS/$svc.service" "$SYSTEMD/$svc.service"
    echo "  installed $svc.service"
done

systemctl daemon-reload

# Enable all services (start on boot)
for svc in zeek cowrie loki promtail honeypot-controller; do
    systemctl enable "$svc"
    echo "  enabled $svc"
done

echo ""
echo "All services installed and enabled."
echo ""
echo "Start everything now:"
echo "  sudo systemctl start loki promtail zeek cowrie honeypot-controller"
echo ""
echo "Check status:"
echo "  sudo systemctl status zeek cowrie loki promtail honeypot-controller"
