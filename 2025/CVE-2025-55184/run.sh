#!/bin/bash
# Quick launcher for CVE-2025-55184 Tool
# Author: CyberTechAjju

clear

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║     🔥 CVE-2025-55184 EXPLOITATION TOOL 🔥                ║"
echo "║            by CyberTechAjju                               ║"
echo "║     \"KEEP LEARNING KEEP HACKING\" - CyberTechAjju          ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if running in virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo "[*] Checking for virtual environment..."
    
    if [ ! -d ".venv" ]; then
        echo "[*] Creating virtual environment..."
        python3 -m venv .venv 2>/dev/null
        
        if [ $? -ne 0 ]; then
            echo "[!] Could not create venv, installing globally..."
            pip3 install --quiet -r requirements.txt 2>/dev/null
        else
            source .venv/bin/activate
            echo "[*] Installing dependencies..."
            pip install --quiet -r requirements.txt
        fi
    else
        source .venv/bin/activate
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

# Run the simplified tool
python3 exploit.py

echo ""
echo "════════════════════════════════════════════════════════════"
echo ""
echo "[✓] Tool exited cleanly"
echo ""
