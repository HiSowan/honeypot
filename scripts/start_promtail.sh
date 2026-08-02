#!/usr/bin/env bash
set -e
sudo mkdir -p /opt/promtail
sudo /opt/promtail/promtail -config.file=/opt/promtail/promtail-config.yaml &
echo "Promtail started."
