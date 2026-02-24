#!/bin/bash
# Snort Performance Monitoring Script
# Measures packet dispatch efficiency and processing rates
#
# Usage: ./perf-monitor.sh [duration_seconds]

DURATION=${1:-10}
INTERFACE="eth0"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Snort Performance Monitor                                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Monitoring for ${DURATION} seconds..."
echo ""

# Get Snort PID
SNORT_PID=$(pgrep -x snort)
if [ -z "$SNORT_PID" ]; then
    echo "ERROR: Snort is not running"
    exit 1
fi
echo "Snort PID: $SNORT_PID"

# ============================================================
# Method 1: Interface Statistics (packets in/out)
# ============================================================
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ 1. Interface Statistics                                        │"
echo "└────────────────────────────────────────────────────────────────┘"

# Get initial counts
RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo 0)
TX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/tx_packets 2>/dev/null || echo 0)
RX_BYTES_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes 2>/dev/null || echo 0)
TX_BYTES_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes 2>/dev/null || echo 0)

sleep $DURATION

# Get final counts
RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo 0)
TX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/tx_packets 2>/dev/null || echo 0)
RX_BYTES_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes 2>/dev/null || echo 0)
TX_BYTES_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes 2>/dev/null || echo 0)

RX_PACKETS=$((RX_AFTER - RX_BEFORE))
TX_PACKETS=$((TX_AFTER - TX_BEFORE))
RX_BYTES=$((RX_BYTES_AFTER - RX_BYTES_BEFORE))
TX_BYTES=$((TX_BYTES_AFTER - TX_BYTES_BEFORE))

RX_PPS=$((RX_PACKETS / DURATION))
TX_PPS=$((TX_PACKETS / DURATION))
RX_BPS=$((RX_BYTES * 8 / DURATION))
TX_BPS=$((TX_BYTES * 8 / DURATION))

echo "Interface: $INTERFACE"
echo "  RX: $RX_PACKETS packets ($RX_PPS pps), $RX_BYTES bytes ($RX_BPS bps)"
echo "  TX: $TX_PACKETS packets ($TX_PPS pps), $TX_BYTES bytes ($TX_BPS bps)"

# ============================================================
# Method 2: Snort Process Statistics
# ============================================================
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ 2. Snort Process Statistics                                    │"
echo "└────────────────────────────────────────────────────────────────┘"

ps -p $SNORT_PID -o pid,pcpu,pmem,vsz,rss,time,cmd --no-headers
echo ""

# CPU usage over time
echo "CPU usage (sampled 5 times):"
for i in 1 2 3 4 5; do
    CPU=$(ps -p $SNORT_PID -o pcpu --no-headers 2>/dev/null | tr -d ' ')
    echo "  Sample $i: ${CPU}%"
    sleep 1
done

# ============================================================
# Method 3: Snort's Built-in Statistics (if available)
# ============================================================
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ 3. Snort Internal Statistics                                   │"
echo "└────────────────────────────────────────────────────────────────┘"

# Send SIGUSR1 to Snort to dump stats to log
echo "Sending SIGUSR1 to Snort to dump statistics..."
kill -USR1 $SNORT_PID 2>/dev/null

sleep 1

# Check for stats in log
if [ -f /var/log/snort/snort.stats ]; then
    echo "From /var/log/snort/snort.stats:"
    tail -20 /var/log/snort/snort.stats
else
    echo "Stats file not found. Check Snort logs:"
    echo "(Stats may be printed to stdout/stderr)"
fi

# ============================================================
# Method 4: Memory and File Descriptors
# ============================================================
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ 4. Resource Usage                                              │"
echo "└────────────────────────────────────────────────────────────────┘"

echo "Memory maps:"
cat /proc/$SNORT_PID/status 2>/dev/null | grep -E "^(VmSize|VmRSS|VmData|VmStk|Threads)"

echo ""
echo "Open file descriptors: $(ls /proc/$SNORT_PID/fd 2>/dev/null | wc -l)"

# ============================================================
# Method 5: System calls (brief strace)
# ============================================================
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ 5. System Call Analysis (2 second sample)                      │"
echo "└────────────────────────────────────────────────────────────────┘"

echo "Top system calls:"
timeout 2 strace -c -p $SNORT_PID 2>&1 | tail -20 || echo "(strace requires privileges)"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Monitoring complete."
