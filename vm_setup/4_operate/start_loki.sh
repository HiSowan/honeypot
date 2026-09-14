#!/usr/bin/env bash
set -e
sudo mkdir -p /opt/loki/data/chunks /opt/loki/data/rules
sudo chown -R loki:loki /opt/loki/data
sudo -u loki /opt/loki/loki -config.file=/opt/loki/loki-config.yaml &
echo "Loki started on port 3100."
