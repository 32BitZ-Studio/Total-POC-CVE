#!/bin/bash
# Network setup for Snort IDS Gateway - NFQUEUE Inline Mode
# Traffic enters on untrusted (eth0/96.x), exits on protected (eth1/95.x)
# NFQUEUE holds packets until Snort renders verdict (ACCEPT/DROP)
#
# This demonstrates CVE-2022-20685 impact:
# When Snort hangs → NFQUEUE fills up → ALL TRAFFIC STOPS
#
# For defensive security research demonstration.

set -e

LOG="/logs/snort-gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Setting up Snort gateway network (NFQUEUE inline mode)..."

# Get IPs from interfaces
ETH0_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
ETH1_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")

log "Detected: eth0=$ETH0_IP, eth1=$ETH1_IP"

# Determine which eth is untrusted (96.x) vs protected (95.x)
if [[ "$ETH0_IP" == 192.168.96.* ]]; then
    UNTRUSTED_IF="eth0"
    PROTECTED_IF="eth1"
    UNTRUSTED_IP="$ETH0_IP"
    PROTECTED_IP="$ETH1_IP"
elif [[ "$ETH1_IP" == 192.168.96.* ]]; then
    UNTRUSTED_IF="eth1"
    PROTECTED_IF="eth0"
    UNTRUSTED_IP="$ETH1_IP"
    PROTECTED_IP="$ETH0_IP"
else
    log "ERROR: Cannot determine network assignment. Expected 192.168.96.x on one interface."
    exit 1
fi

log "Network mapping:"
log "  Untrusted: $UNTRUSTED_IF ($UNTRUSTED_IP) - traffic enters here"
log "  Protected: $PROTECTED_IF ($PROTECTED_IP) - traffic exits to PLC"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
log "IP forwarding enabled"

# Disable reverse path filtering (required for asymmetric routing)
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$UNTRUSTED_IF/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$PROTECTED_IF/rp_filter
log "Reverse path filtering disabled"

# Clear existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# NAT: Rewrite destination to PLC, source for return traffic
# Match on any interface since Docker may route to either network
iptables -t nat -A PREROUTING -p tcp --dport 502 -j DNAT --to-destination 192.168.95.2:502
iptables -t nat -A POSTROUTING -o $PROTECTED_IF -j MASQUERADE

# NFQUEUE: Send ALL forwarded Modbus traffic to Snort for inspection
# Match by destination/source (PLC), not by interface - handles Docker's routing
iptables -A FORWARD -d 192.168.95.2 -p tcp --dport 502 -j NFQUEUE --queue-num 0
iptables -A FORWARD -s 192.168.95.2 -p tcp --sport 502 -j NFQUEUE --queue-num 0

log "iptables configured for NFQUEUE inline mode"
log ""
log "╔════════════════════════════════════════════════════════════════╗"
log "║  NFQUEUE INLINE ARCHITECTURE                                   ║"
log "╠════════════════════════════════════════════════════════════════╣"
log "║                                                                ║"
log "║  Traffic Flow:                                                 ║"
log "║                                                                ║"
log "║    Host:503 → Container:502 → iptables DNAT → NFQUEUE          ║"
log "║                                                  ↓              ║"
log "║                                            Snort inspects       ║"
log "║                                            ACCEPT / DROP        ║"
log "║                                                  ↓              ║"
log "║                                            PLC (95.2:502)       ║"
log "║                                                                ║"
log "╠════════════════════════════════════════════════════════════════╣"
log "║  CVE-2022-20685 Impact:                                        ║"
log "║                                                                ║"
log "║  When Snort hangs in infinite loop:                            ║"
log "║    • No verdict returned to NFQUEUE                            ║"
log "║    • Packets pile up in kernel queue                           ║"
log "║    • ALL TRAFFIC STOPS (true DoS, not just blindness)         ║"
log "║                                                                ║"
log "╚════════════════════════════════════════════════════════════════╝"
