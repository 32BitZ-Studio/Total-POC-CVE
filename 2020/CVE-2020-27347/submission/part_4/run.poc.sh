#!/usr/bin/env bash
set -euo pipefail

# path to the directory containing the Dockerfile and utility scripts
export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
export ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"

DOCKERFILE_DIR="${ROOT_DIR}/submission/part_4/environment"

echo "Starting Docker image build and tests for CVE-2020-27347."

# build docker image
pushd "${DOCKERFILE_DIR}"
echo -e "\n=========================================="
echo "Building Docker image 'tmux-cve-2020-27347'..."
echo "=========================================="
docker build -t tmux-cve-2020-27347 .
echo "Docker image built successfully."

# Test exploit in different versions of tmux
# a) vulnerable version (3.1b)
docker run --name "tmux-cve-2020-27347-vuln" \
  --rm -it tmux-cve-2020-27347 \
  /bin/bash -c "./test_vulnerable.sh"
echo "Vulnerable version test completed. Review output above for crash details."

# b) fixed version (3.1b + patch)
docker run --name "tmux-cve-2020-27347-fixed" \
  --rm -it tmux-cve-2020-27347 \
  /bin/bash -c "./test_fixed.sh"
echo "Fixed version test completed. Review output above to confirm no crash."

popd # back to original directory
echo -e "\nAll Docker tests for CVE-2020-27347 executed successfully."
echo "Please review the output for results of vulnerable and fixed versions."
