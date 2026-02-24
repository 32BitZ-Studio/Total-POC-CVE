#!/bin/bash
set -e

LOG="/logs/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Setting up network bridges and tap interfaces..."

# Get IPs from interfaces
ETH0_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)
ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)

log "Detected: eth0=$ETH0_IP, eth1=$ETH1_IP"

# Bridge naming follows eth: br0=eth0, br1=eth1
# But tap assignment follows seL4's expectation: tap0=untrusted(96.x), tap1=protected(95.x)

# Determine which eth is untrusted (96.x) vs protected (95.x)
if [[ "$ETH0_IP" == 192.168.96.* ]]; then
    UNTRUSTED_BR="br0"
    UNTRUSTED_ETH="eth0"
    UNTRUSTED_IP="$ETH0_IP"
    PROTECTED_BR="br1"
    PROTECTED_ETH="eth1"
    PROTECTED_IP="$ETH1_IP"
elif [[ "$ETH1_IP" == 192.168.96.* ]]; then
    UNTRUSTED_BR="br1"
    UNTRUSTED_ETH="eth1"
    UNTRUSTED_IP="$ETH1_IP"
    PROTECTED_BR="br0"
    PROTECTED_ETH="eth0"
    PROTECTED_IP="$ETH0_IP"
else
    log "ERROR: Cannot determine network assignment. Expected 192.168.96.x on one interface."
    exit 1
fi

log "Network detection: $UNTRUSTED_ETH=untrusted(96.x), $PROTECTED_ETH=protected(95.x)"

# Create tap interfaces
ip tuntap add dev tap0 mode tap
ip tuntap add dev tap1 mode tap

# Create bridges (named after their eth interface)
ip link add br0 type bridge
ip link add br1 type bridge

# Remove IPs from eth interfaces
ip addr del "$ETH0_IP" dev eth0 || true
ip addr del "$ETH1_IP" dev eth1 || true

# br0 = eth0, br1 = eth1
ip link set eth0 master br0
ip link set eth1 master br1
ip addr add "$ETH0_IP" dev br0
ip addr add "$ETH1_IP" dev br1

# tap0 = untrusted (seL4 net0), tap1 = protected (seL4 net1)
# These must follow seL4's expectations, not the bridge naming
ip link set tap0 master "$UNTRUSTED_BR"
ip link set tap1 master "$PROTECTED_BR"

# Bring up all interfaces
ip link set tap0 up
ip link set tap1 up
ip link set br0 up
ip link set br1 up
ip link set eth0 up
ip link set eth1 up

log "Bridge mapping: br0=eth0, br1=eth1"
log "Tap mapping: tap0->$UNTRUSTED_BR (untrusted), tap1->$PROTECTED_BR (protected)"

# Enable proxy ARP and IP forwarding
echo 1 > /proc/sys/net/ipv4/conf/br0/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/br1/proxy_arp
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable bridge netfilter so iptables can process bridged traffic
# This is required for SNAT to work on traffic from seL4 through the bridge
modprobe br_netfilter 2>/dev/null || true
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true

# Add proxy ARP entries for seL4's IPs on the correct bridges
ip neigh add proxy 192.168.96.2 dev "$UNTRUSTED_BR" || true
ip neigh add proxy 192.168.95.1 dev "$PROTECTED_BR" || true

# Policy routing to forward traffic to seL4 while preserving PLC destination IP
# This mimics real hardware where packets to 192.168.95.2 are forwarded through seL4

# 1. DNAT incoming port 502 to PLC's IP (so seL4 sees correct destination)
iptables -t nat -A PREROUTING -p tcp --dport 502 -j DNAT --to-destination 192.168.95.2:502

# 2. Mark ALL port 502 packets BEFORE DNAT (mangle runs before nat)
#    We can't check -d 192.168.95.2 here because DNAT hasn't happened yet
iptables -t mangle -A PREROUTING -p tcp --dport 502 -j MARK --set-mark 100

# 3. Policy routing: marked packets use custom routing table
ip rule add fwmark 100 table 100 || true

# 4. Custom route table: send 192.168.95.2 to seL4 (192.168.96.2) via untrusted bridge
ip route add 192.168.95.2/32 via 192.168.96.2 dev "$UNTRUSTED_BR" table 100 || true

# 5. NO SNAT - rely on proxy ARP for seL4's IP (192.168.95.1)
# The gateway responds to ARPs for 192.168.95.1, so PLC can route responses
# directly to that IP, which the bridge forwards to tap1 (seL4)
PROTECTED_IP_ADDR="${PROTECTED_IP%/*}"  # Strip /24 suffix

# 6. MASQUERADE only for traffic NOT from seL4 (to avoid breaking return path)
iptables -t nat -A POSTROUTING ! -s 192.168.95.1 -j MASQUERADE
iptables -A FORWARD -p tcp -d 192.168.95.2 --dport 502 -j ACCEPT
iptables -A FORWARD -p tcp -s 192.168.95.2 --sport 502 -j ACCEPT

log "Network setup complete"
log "  br0: eth0, br1: eth1"
log "  tap0 -> $UNTRUSTED_BR (seL4 net0, untrusted 192.168.96.x)"
log "  tap1 -> $PROTECTED_BR (seL4 net1, protected 192.168.95.x)"
log "  Proxy ARP: 192.168.96.2 on $UNTRUSTED_BR, 192.168.95.1 on $PROTECTED_BR"
log "  Policy routing: port 502 -> DNAT 192.168.95.2 -> via seL4 (192.168.96.2)"
log "  No SNAT: PLC responds to 192.168.95.1 via proxy ARP -> tap1 -> seL4"
