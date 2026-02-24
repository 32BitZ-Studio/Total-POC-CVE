#!/bin/bash
# Snort Demo launcher - Creates tmux session with 3 panes
# (Does not require seL4 kernel image)
#
# Layout:
# ┌─────────────────────────────────────┐
# │            PLC Container            │
# │            Port 5020                │
# ├──────────────────┬──────────────────┤
# │   Snort IDS      │  User Terminal   │
# │   Port 503       │   (commands)     │
# └──────────────────┴──────────────────┘
#
# Usage: ./scripts/demo-snort.sh

set -e

SESSION="snort-demo"

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create new session with first pane (PLC)
tmux new-session -d -s "$SESSION" -n "demo"

# Split horizontally (top/bottom)
tmux split-window -v -t "$SESSION"

# Split bottom pane vertically (left/right)
tmux select-pane -t "$SESSION:0.1"
tmux split-window -h -t "$SESSION"

# Now we have 3 panes:
# Pane 0: top         (PLC)
# Pane 1: bottom-left (Snort)
# Pane 2: bottom-right (User terminal)

# Send commands to each pane
# Pane 0: PLC
tmux send-keys -t "$SESSION:0.0" "echo '=== PLC Container (Port 5020) ===' && sudo docker compose up plc" C-m

# Pane 1: Snort IDS
tmux send-keys -t "$SESSION:0.1" "echo '=== Snort IDS (Port 503) ===' && echo 'Waiting for PLC...' && sleep 3 && sudo docker compose up snort" C-m

# Pane 2: User terminal with helpful message
tmux send-keys -t "$SESSION:0.2" "cat << 'EOF'
╔══════════════════════════════════════╗
║ CVE-2022-20685 Demo                  ║
║ Snort IDS DoS Attack                 ║
╠══════════════════════════════════════╣
║ 1. Wait for containers to start      ║
║                                      ║
║ 2. Verify Snort works:               ║
║  nc -w2 localhost 503                ║
║                                      ║
║ 3. Attack Snort IDS:                 ║
║  ./cve_tools/cve_20685_attack \\      ║
║    127.0.0.1 503                     ║
║                                      ║
║ 4. Verify frozen (timeout):          ║
║  nc -w5 localhost 503                ║
║                                      ║
║ 5. Check CPU (should be 100%):       ║
║  docker exec ics-snort top -bn1      ║
║                                      ║
║ Reset:                               ║
║  docker compose restart snort        ║
╚══════════════════════════════════════╝
EOF
" C-m

# Select the user terminal pane
tmux select-pane -t "$SESSION:0.2"

# Attach to session
tmux attach-session -t "$SESSION"
