#!/usr/bin/env bash
# Enable SSH password authentication so you can SSH in from Windows.
# Run on the VM: bash scripts/enable_ssh_password.sh

set -euo pipefail

sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh
echo "Done — password auth enabled. SSH in with: ssh vboxuser@127.0.0.1 -p 2222"
