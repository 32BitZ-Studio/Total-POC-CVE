#!/bin/bash
# Demo launcher wrapper - defaults to ARM for backward compatibility
#
# For architecture-specific demos:
#   ./scripts/demo-arm.sh  - ARM gateway (QEMU emulation)
#   ./scripts/demo-x86.sh  - x86 gateway (KVM acceleration)
#
# Usage: ./scripts/demo.sh

exec "$(dirname "$0")/demo-arm.sh"
