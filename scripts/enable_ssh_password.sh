#!/usr/bin/env bash
# Enable SSH password authentication — handles Ubuntu 24.04 override files.
# Run on the VM: bash scripts/enable_ssh_password.sh

set -euo pipefail

# Fix main config
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Fix any override files in sshd_config.d (Ubuntu 22.04+ drops overrides here)
if ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/*.conf
fi

# Write an explicit override that wins regardless
echo "PasswordAuthentication yes" | sudo tee /etc/ssh/sshd_config.d/99-password-auth.conf

sudo systemctl restart ssh

echo "Current PasswordAuthentication settings:"
grep -r PasswordAuthentication /etc/ssh/ 2>/dev/null || true

echo ""
echo "Done. SSH in from Windows with: ssh vboxuser@127.0.0.1 -p 2222"
