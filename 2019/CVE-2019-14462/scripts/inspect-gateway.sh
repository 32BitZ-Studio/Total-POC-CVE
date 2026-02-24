#!/bin/bash
# Inspect gateway container network configuration

echo "=========================================="
echo "Gateway Container Network Inspection"
echo "=========================================="

echo ""
echo "=== 1. Container Status ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAME|gateway|plc"

echo ""
echo "=== 2. Network Interfaces (ip addr) ==="
docker exec ics-gateway ip addr show

echo ""
echo "=== 3. Link Status (ip link) ==="
docker exec ics-gateway ip link show

echo ""
echo "=== 4. Bridge Members ==="
docker exec ics-gateway bridge link show 2>/dev/null || echo "(bridge command not available)"

echo ""
echo "=== 5. Bridge Details (brctl) ==="
docker exec ics-gateway brctl show 2>/dev/null || echo "(brctl not available)"

echo ""
echo "=== 6. ARP Table ==="
docker exec ics-gateway arp -a 2>/dev/null || docker exec ics-gateway ip neigh show

echo ""
echo "=== 7. Routing Table ==="
docker exec ics-gateway ip route show

echo ""
echo "=== 8. iptables NAT Rules ==="
docker exec ics-gateway iptables -t nat -L -n -v 2>/dev/null || echo "(iptables not available)"

echo ""
echo "=== 9. iptables FORWARD Rules ==="
docker exec ics-gateway iptables -L FORWARD -n -v 2>/dev/null || echo "(iptables not available)"

echo ""
echo "=== 10. IP Forwarding Status ==="
docker exec ics-gateway cat /proc/sys/net/ipv4/ip_forward

echo ""
echo "=== 11. Proxy ARP Status ==="
docker exec ics-gateway cat /proc/sys/net/ipv4/conf/br0/proxy_arp 2>/dev/null && echo "  (br0 proxy_arp)"
docker exec ics-gateway cat /proc/sys/net/ipv4/conf/br1/proxy_arp 2>/dev/null && echo "  (br1 proxy_arp)"

echo ""
echo "=== 12. Ping Tests ==="
echo "Gateway -> PLC (192.168.95.2):"
docker exec ics-gateway ping -c 2 -W 1 192.168.95.2 2>&1

echo ""
echo "=== 13. TCP Test to PLC ==="
docker exec ics-gateway timeout 2 nc -zv 192.168.95.2 502 2>&1

echo ""
echo "=== 14. PLC Container Network ==="
docker exec ics-plc ip addr show 2>/dev/null | grep -E "inet |eth"

echo ""
echo "=== 15. Gateway Log (last 20 lines) ==="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
tail -20 "${SCRIPT_DIR}/../logs/gateway.log" 2>/dev/null || docker logs ics-gateway 2>&1 | tail -20

echo ""
echo "=========================================="
echo "Inspection Complete"
echo "=========================================="
