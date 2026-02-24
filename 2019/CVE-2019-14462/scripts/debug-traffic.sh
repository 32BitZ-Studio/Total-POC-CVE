#!/bin/bash
# Debug network traffic on gateway bridges

echo "=========================================="
echo "Traffic Debug for seL4 Gateway"
echo "=========================================="

echo ""
echo "=== 1. Check if PLC is reachable from gateway container ==="
docker exec ics-gateway ping -c 1 -W 1 192.168.95.2

echo ""
echo "=== 2. Check ARP entries for PLC (192.168.95.2) ==="
docker exec ics-gateway ip neigh show | grep 192.168.95

echo ""
echo "=== 3. Check if seL4 can ARP for PLC ==="
echo "Watching for ARP traffic on br1 (5 seconds)..."
echo "In another terminal, try: modscan -t 127.0.0.1 -p 502"
timeout 5 docker exec ics-gateway tcpdump -i br1 -n arp 2>/dev/null || \
    echo "(tcpdump not available, install with: docker exec ics-gateway apt-get update && apt-get install -y tcpdump)"

echo ""
echo "=== 4. Check TCP traffic on br1 to PLC ==="
echo "Watching for TCP traffic to 192.168.95.2:502 (5 seconds)..."
timeout 5 docker exec ics-gateway tcpdump -i br1 -n "host 192.168.95.2 and port 502" 2>/dev/null || \
    echo "(tcpdump not available)"

echo ""
echo "=== 5. Bridge forwarding database ==="
docker exec ics-gateway bridge fdb show br br0 2>/dev/null | head -10
docker exec ics-gateway bridge fdb show br br1 2>/dev/null | head -10

echo ""
echo "=== 6. Check for seL4's MAC in bridge FDB ==="
echo "seL4 net0 MAC: 52:54:00:12:34:56"
echo "seL4 net1 MAC: 52:54:00:12:34:57"
docker exec ics-gateway bridge fdb show | grep -E "52:54:00:12:34:5[67]"

echo ""
echo "=== 7. Check bridge VLAN filtering ==="
docker exec ics-gateway cat /sys/class/net/br0/bridge/vlan_filtering
docker exec ics-gateway cat /sys/class/net/br1/bridge/vlan_filtering

echo ""
echo "=== 8. Check if conntrack is tracking connections ==="
docker exec ics-gateway cat /proc/net/nf_conntrack 2>/dev/null | grep 192.168.95 | head -5 || \
    docker exec ics-gateway conntrack -L 2>/dev/null | grep 192.168.95 | head -5 || \
    echo "(conntrack not available)"

echo ""
echo "=========================================="
echo "Debug Complete"
echo "=========================================="
