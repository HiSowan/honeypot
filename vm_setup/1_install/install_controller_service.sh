#!/usr/bin/env bash
# Install the honeypot controller as a systemd service.
# After this, the controller starts automatically on boot.
#
# Usage: sudo bash scripts/install_controller_service.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_SRC="$REPO_DIR/scripts/honeypot-controller.service"
SERVICE_DST="/etc/systemd/system/honeypot-controller.service"
LOG_DIR="/var/log/honeypot"

mkdir -p "$LOG_DIR"

cp "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
systemctl enable honeypot-controller.service

echo "Service installed and enabled."
echo ""
echo "Control commands:"
echo "  sudo systemctl start   honeypot-controller"
echo "  sudo systemctl stop    honeypot-controller"
echo "  sudo systemctl status  honeypot-controller"
echo "  sudo journalctl -u honeypot-controller -f"
echo ""
echo "To enable live firewall/ML blocking, edit $SERVICE_DST and set:"
echo "  Environment=FIREWALL_LIVE=1"
echo "  Environment=ML_LIVE=1"
echo "Then: sudo systemctl daemon-reload && sudo systemctl restart honeypot-controller"
