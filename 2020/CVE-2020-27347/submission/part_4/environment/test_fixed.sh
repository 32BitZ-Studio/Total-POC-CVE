#!/bin/bash
set -euo pipefail

# Source the common test script
source ./run_tmux_cve_test.sh

# donwload the patch for tmux
PATCH_URL="https://github.com/tmux/tmux/commit/a868bacb46e3c900530bed47a1c6f85b0fbe701c.diff"
curl $PATCH_URL -o tmux.patch

# Run the test for the fixed version
run_tmux_test \
  "6a33a12798b2afeee6fb7bba74d86d628137921e" \
  "fixed version (patched 3.1b)" \
  "no_crash" \
  "tmux.patch"
