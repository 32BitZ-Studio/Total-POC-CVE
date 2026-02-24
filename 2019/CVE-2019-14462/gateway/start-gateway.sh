#!/bin/bash
set -e

LOG="/logs/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

ARCH="${GATEWAY_ARCH:-arm}"
log "Starting seL4 ICS Gateway (architecture: $ARCH)..."

# Setup network first
/usr/local/bin/setup-network.sh

# Configure QEMU based on architecture
case "$ARCH" in
    arm)
        IMAGE="/sel4-image/capdl-loader-image-arm-qemu-arm-virt"
        QEMU_CMD="qemu-system-arm"
        QEMU_MACHINE="-machine virt,virtualization=on,highmem=off,secure=off"
        QEMU_CPU="-cpu cortex-a15"
        QEMU_MEMORY="-m size=1024"
        QEMU_EXTRA="-global virtio-mmio.force-legacy=false"
        NET0_DEV="-device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56"
        NET1_DEV="-device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57"
        ;;
    x86|x86_64)
        IMAGE="/sel4-image/capdl-loader-image-x86_64-pc99"
        QEMU_CMD="qemu-system-x86_64"
        QEMU_MACHINE="-machine q35"
        QEMU_CPU=""
        QEMU_MEMORY="-m 2G"
        QEMU_EXTRA=""
        NET0_DEV="-device e1000,netdev=net0,mac=52:54:00:12:34:56"
        NET1_DEV="-device e1000,netdev=net1,mac=52:54:00:12:34:57"

        # Enable KVM if available
        if [ -c /dev/kvm ] && [ -w /dev/kvm ]; then
            log "KVM acceleration enabled"
            QEMU_EXTRA="-enable-kvm -cpu host"
        else
            log "WARNING: KVM not available, using TCG emulation"
        fi
        ;;
    *)
        log "ERROR: Unknown architecture: $ARCH"
        exit 1
        ;;
esac

# Check for seL4 image
if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    exit 1
fi

log "Launching QEMU with seL4..."
log "  net0 (tap0): 192.168.96.2 (untrusted)"
log "  net1 (tap1): 192.168.95.1 (protected)"

# Run QEMU, timestamp all output
$QEMU_CMD \
  $QEMU_MACHINE \
  $QEMU_CPU \
  -nographic \
  $QEMU_MEMORY \
  $QEMU_EXTRA \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  $NET0_DEV \
  -netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
  $NET1_DEV \
  -kernel "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
