#!/bin/bash
# Dual_EC_DRBG Backdoor PoC - Launcher Script
# For educational purposes only

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}  Dual_EC_DRBG Backdoor - Educational PoC   ${NC}"
echo -e "${BLUE}==============================================${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[!] Virtual environment not found.${NC}"
    echo -e "${BLUE}[+] Creating virtual environment with pyenv...${NC}"
    
    # Check if pyenv is available
    if command -v pyenv &> /dev/null; then
        pyenv local 3.12.12
    fi
    
    python3 -m venv venv
    echo -e "${GREEN}[✓] Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}[+] Activating virtual environment...${NC}"
source venv/bin/activate

# Check if dependencies are installed
if ! python3 -c "import ecdsa" 2>/dev/null; then
    echo -e "${YELLOW}[!] Dependencies not installed.${NC}"
    echo -e "${BLUE}[+] Installing dependencies...${NC}"
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
fi

echo -e "${GREEN}[✓] Environment ready!${NC}"
echo ""
echo -e "${BLUE}Starting Jupyter Notebook...${NC}"
echo ""

# Launch Jupyter
jupyter notebook dual_ec_drbg_backdoor_poc.ipynb
