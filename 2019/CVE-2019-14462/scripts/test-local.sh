#!/bin/bash
# Local test script for seL4 gateway image (no Docker, no root required)
# Port 5502 on host forwards to port 502 in guest

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="$SCRIPT_DIR/capdl-loader-image-arm-qemu-arm-virt"

if [ ! -f "$IMAGE" ]; then
    echo "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

echo "Starting seL4 gateway locally..."
echo "  Host port 5502 -> Guest port 502 (net0)"
echo "  Guest 192.168.95.2:502 -> Host localhost:5020 (net1)"
echo "  Press Ctrl+A then X to exit QEMU"
echo ""

qemu-system-arm \
  -machine virt,virtualization=on,highmem=off,secure=off \
  -cpu cortex-a15 \
  -nographic \
  -m size=1024 \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=net0,hostfwd=tcp::5502-:502 \
  -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
  -netdev user,id=net1,guestfwd=tcp:192.168.95.2:502-cmd:"nc 127.0.0.1 5020" \
  -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57 \
  -kernel "$IMAGE"
