#!/bin/bash
set -euo pipefail

# Source the common test script
source ./run_tmux_cve_test.sh

# Run the test for the vulnerable version
run_tmux_test \
  "6a33a12798b2afeee6fb7bba74d86d628137921e" \
  "vulnerable version (3.1b)" \
  "crash"
