#!/bin/bash
# Demo launcher (x86) - Creates tmux session with 4 quadrants
#
# Uses x86 seL4 gateway with KVM acceleration (if available)
#
# Layout:
# ┌─────────────────┬─────────────────┐
# │   PLC (plc)     │  seL4 Gateway   │
# │   Port 5020     │   Port 502      │
# ├─────────────────┼─────────────────┤
# │  Snort IDS      │  User Terminal  │
# │   Port 503      │   (commands)    │
# └─────────────────┴─────────────────┘
#
# Usage: ./scripts/demo-x86.sh

set -e

SESSION="ics-demo"

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create new session with first pane (PLC)
tmux new-session -d -s "$SESSION" -n "demo"

# Split horizontally (top/bottom)
tmux split-window -v -t "$SESSION"

# Split top pane vertically (left/right)
tmux select-pane -t "$SESSION:0.0"
tmux split-window -h -t "$SESSION"

# Split bottom pane vertically (left/right)
tmux select-pane -t "$SESSION:0.2"
tmux split-window -h -t "$SESSION"

# Now we have 4 panes:
# Pane 0: top-left     (PLC)
# Pane 1: top-right    (Gateway)
# Pane 2: bottom-left  (Snort)
# Pane 3: bottom-right (User terminal)

# Send commands to each pane
# Pane 0: PLC
tmux send-keys -t "$SESSION:0.0" "echo '=== PLC Container (Port 5020) ===' && sleep 1 && sudo docker compose up plc" C-m

# Pane 1: seL4 Gateway (x86 with KVM)
tmux send-keys -t "$SESSION:0.1" "echo '=== seL4 Gateway - x86 (Port 502) ===' && echo 'Waiting for PLC...' && sleep 5 && sudo GATEWAY_ARCH=x86 docker compose up gateway" C-m

# Pane 2: Snort IDS
tmux send-keys -t "$SESSION:0.2" "echo '=== Snort IDS (Port 503) ===' && echo 'Waiting for PLC...' && sleep 5 && sudo docker compose up snort" C-m

# Pane 3: User terminal with helpful message
tmux send-keys -t "$SESSION:0.3" "cat << 'EOF'
ICS Gateway Demo (x86) - CVE Attack Tools

ARCHITECTURE: x86_64 (KVM acceleration if available)

PORTS:
  502   seL4 gateway (protocol-break)
  503   Snort IDS (packet-forwarding)
  5020  Direct PLC access (no protection)

CVE-2019-14462: libmodbus heap overflow
  ./cve_tools/cve_14462_attack <IP> <PORT>
  Example: ./cve_tools/cve_14462_attack 127.0.0.1 5020

CVE-2022-0367: libmodbus heap underflow (ASAN build)
  ./cve_tools/cve_0367_attack <IP> <PORT> [ADDR] [VALUE]
  Args: ADDR=write address (default 50), VALUE=hex value (default 0xDEAD)
  Example: ./cve_tools/cve_0367_attack 127.0.0.1 5020
  Example: ./cve_tools/cve_0367_attack 127.0.0.1 5020 50 0xBEEF

CVE-2022-20685: Snort Modbus preprocessor DoS
  ./cve_tools/cve_20685_attack <IP> <PORT>
  Example: ./cve_tools/cve_20685_attack 127.0.0.1 503
  Verify:  sudo docker exec ics-snort top -bn1 | grep snort

Restart: sudo docker compose restart
EOF
" C-m

# Select the user terminal pane
tmux select-pane -t "$SESSION:0.3"

# Attach to session
tmux attach-session -t "$SESSION"
