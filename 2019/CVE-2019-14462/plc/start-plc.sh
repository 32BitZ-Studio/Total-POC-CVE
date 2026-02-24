#!/bin/bash
#
# FrostyGoop District Heating Simulation
# Startup script
#

set -e

LOG_FILE="${LOG_FILE:-/logs/plc.log}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Detect which libmodbus version is installed
if pkg-config --exists libmodbus 2>/dev/null; then
    LIBMODBUS_VERSION=$(pkg-config --modversion libmodbus 2>/dev/null || echo "unknown")
else
    LIBMODBUS_VERSION="unknown"
fi

# Determine vulnerability type based on build
if [ -n "${ASAN_OPTIONS:-}" ]; then
    CVE_INFO="CVE-2022-0367 (ASAN build)"
else
    CVE_INFO="CVE-2019-14462"
fi

# Log startup
{
    echo "========================================"
    echo "FrostyGoop District Heating Simulation"
    echo "Starting at $(date)"
    echo "libmodbus ${LIBMODBUS_VERSION} (VULNERABLE - ${CVE_INFO})"
    echo "========================================"
} | tee -a "$LOG_FILE"

# Execute the controller
exec /src/heating_controller
