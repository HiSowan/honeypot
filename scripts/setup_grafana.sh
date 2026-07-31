#!/usr/bin/env bash
set -e
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Copy provisioning files
sudo cp -r "$REPO_DIR/config/grafana/provisioning/datasources" /etc/grafana/provisioning/
sudo cp -r "$REPO_DIR/config/grafana/provisioning/dashboards" /etc/grafana/provisioning/

# Copy dashboard JSON
sudo mkdir -p /etc/grafana/dashboards
sudo cp "$REPO_DIR/dashboards/honeypot_overview.json" /etc/grafana/dashboards/

sudo systemctl restart grafana-server
echo "Grafana provisioning applied and service restarted."
