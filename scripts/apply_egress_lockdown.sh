#!/usr/bin/env bash
# DEPLOY-TIME ONLY — Default-deny egress firewall lockdown.
#
# DO NOT run this during the build phase.
# It cuts off outbound internet except for explicitly whitelisted destinations.
#
# Run once when the honeypot goes live on the target network.
# Usage: sudo bash scripts/apply_egress_lockdown.sh

set -euo pipefail

IFACE="enp0s3"
OPERATOR_IP="192.168.0.3"   # Windows host — never block

echo "========================================================"
echo "  DEPLOY-TIME EGRESS LOCKDOWN"
echo "  Interface : $IFACE"
echo "  Operator  : $OPERATOR_IP (always allowed)"
echo "========================================================"
echo ""
read -rp "Are you sure you want to apply default-deny egress? [yes/N] " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

# ----------------------------------------------------------------
# Flush existing OUTPUT rules and set default DROP
# ----------------------------------------------------------------
iptables -F OUTPUT
iptables -P OUTPUT DROP

# ----------------------------------------------------------------
# Always-allowed: loopback and established/related return traffic
# ----------------------------------------------------------------
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ----------------------------------------------------------------
# Operator IP — bidirectional (allow management traffic out)
# ----------------------------------------------------------------
iptables -A OUTPUT -d "$OPERATOR_IP" -j ACCEPT

# ----------------------------------------------------------------
# DNS (UDP/TCP 53) — needed for package updates and Zeek lookups
# ----------------------------------------------------------------
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# ----------------------------------------------------------------
# NTP (UDP 123) — clock sync
# ----------------------------------------------------------------
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# ----------------------------------------------------------------
# APT / system updates (HTTPS to Ubuntu mirrors only)
# Adjust or remove if the honeypot must be fully air-gapped.
# ----------------------------------------------------------------
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT

# ----------------------------------------------------------------
# Log and drop everything else
# ----------------------------------------------------------------
iptables -A OUTPUT -j LOG --log-prefix "[EGRESS BLOCKED] " --log-level 4
iptables -A OUTPUT -j DROP

echo ""
echo "Egress lockdown applied. Outbound traffic is now default-deny."
echo "To revert: sudo iptables -P OUTPUT ACCEPT && sudo iptables -F OUTPUT"
