#!/usr/bin/env bash
# Redirect standard honeypot ports to Cowrie listeners.
#
#   TCP 22  → 2222  (SSH  → Cowrie)
#   TCP 23  → 2223  (Telnet → Cowrie)
#
# The VirtualBox host (10.0.2.2) is excluded from the SSH redirect so
# management SSH from the host still reaches the real sshd on port 22.
#
# Safe to run during the build phase — the VM is behind VirtualBox NAT
# so no external traffic arrives until the honeypot is deployed.
#
# Usage: sudo bash scripts/setup_cowrie_portfwd.sh

set -euo pipefail

IFACE="enp0s3"
HOST_IP="10.0.2.2"   # VirtualBox NAT host — skip redirect for management SSH

echo "Setting up Cowrie port forwarding on $IFACE ..."

# Remove any existing duplicate rules first
iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 22 \! -s "$HOST_IP" -j REDIRECT --to-port 2222 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 23 -j REDIRECT --to-port 2223 2>/dev/null || true

# SSH: redirect all port-22 traffic to Cowrie, except from the host
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 22 \! -s "$HOST_IP" -j REDIRECT --to-port 2222

# Telnet: redirect all port-23 traffic to Cowrie
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 23 -j REDIRECT --to-port 2223

echo "Port forwarding active:"
echo "  TCP 22 → 2222  (Cowrie SSH, host $HOST_IP excluded)"
echo "  TCP 23 → 2223  (Cowrie Telnet)"
echo ""

# Persist across reboots
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
    echo "Rules persisted via netfilter-persistent."
else
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo "Rules saved to /etc/iptables/rules.v4"
    echo "To auto-restore on reboot: sudo apt install iptables-persistent"
fi
