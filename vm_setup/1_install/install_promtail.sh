#!/usr/bin/env bash
set -e
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Download Promtail binary matching Loki version
curl -O -L "https://github.com/grafana/loki/releases/download/v3.0.0/promtail-linux-amd64.zip"
unzip -o promtail-linux-amd64.zip
sudo mv promtail-linux-amd64 /opt/promtail/promtail
sudo chmod +x /opt/promtail/promtail
rm promtail-linux-amd64.zip

# Copy config
sudo cp "$REPO_DIR/config/promtail/promtail-config.yaml" /opt/promtail/promtail-config.yaml

echo "Promtail installed."
