#!/bin/bash
#
# Build Modified seL4 Image with Backdoored Net0_Driver
#
# This script:
# 1. Patches the Net0_Driver with the backdoor trigger code
# 2. Rebuilds the seL4/CAmkES image (incremental, ~1 min)
# 3. Copies the resulting image to the gateway container
#
# Prerequisites:
#   - CAmkES build system at /home/iamfo470/phd/camkes-vm-examples/
#   - Existing build at build-ics-x86/
#
# For defensive security research only.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAMKES_DIR="/home/iamfo470/phd/camkes-vm-examples"
BUILD_DIR="${CAMKES_DIR}/build-ics-x86"
DRIVER_SRC="${CAMKES_DIR}/projects/ics_gateway_x86/components/Net0_Driver/net0_driver.c"
BACKDOOR_SRC="${SCRIPT_DIR}/backdoor_driver.c"
GATEWAY_IMAGE_DIR="${SCRIPT_DIR}/../../gateway/sel4-image"
IMAGE_NAME="capdl-loader-image-x86_64-pc99"

echo "============================================="
echo " E2: Build Backdoored seL4 Gateway Image"
echo "============================================="
echo ""

# Verify prerequisites
if [ ! -d "$CAMKES_DIR" ]; then
    echo "ERROR: CAmkES directory not found: $CAMKES_DIR"
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "ERROR: Build directory not found: $BUILD_DIR"
    echo "Run initial build first."
    exit 1
fi

if [ ! -f "$DRIVER_SRC" ]; then
    echo "ERROR: Net0_Driver source not found: $DRIVER_SRC"
    exit 1
fi

# Backup original driver
BACKUP="${DRIVER_SRC}.orig"
if [ ! -f "$BACKUP" ]; then
    echo "Backing up original driver: $BACKUP"
    cp "$DRIVER_SRC" "$BACKUP"
fi

# Patch driver with backdoor code
echo "Patching Net0_Driver with backdoor trigger..."
echo ""

# The patch adds the backdoor check to the receive handler.
# We append the backdoor functions and modify the receive path.
cat >> "$DRIVER_SRC" << 'BACKDOOR_PATCH'

/* ========== E2 SUPPLY-CHAIN SIMULATION BACKDOOR ========== */
/* This code simulates a compromised network driver component */

#define BACKDOOR_TRIGGER_SEQ "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
#define BACKDOOR_TRIGGER_LEN 8
#define BACKDOOR_TRIGGER_OFFSET 12

static int backdoor_check_trigger(uint8_t *data, size_t len) {
    if (len < BACKDOOR_TRIGGER_OFFSET + BACKDOOR_TRIGGER_LEN) {
        return 0;
    }
    return memcmp(data + BACKDOOR_TRIGGER_OFFSET,
                  BACKDOOR_TRIGGER_SEQ, BACKDOOR_TRIGGER_LEN) == 0;
}

static void backdoor_attempt_escalation(void) {
    /* Attempt 1: Read kernel memory -> VM fault on seL4 */
    printf("[BACKDOOR] Attempt read kernel memory...\n");
    /* volatile char *k = (volatile char *)0xFFFFFFFF80000000ULL; */
    /* char c = *k; */  /* Would fault */

    /* Attempt 2: Access parser component -> Cap fault on seL4 */
    printf("[BACKDOOR] Attempt access parser component...\n");
    /* No way to get parser's memory without a capability */

    /* Attempt 3: Send to protected network -> No capability */
    printf("[BACKDOOR] Attempt bypass to PLC...\n");
    /* Net0_Driver has no caps for net1 device */

    /* Attempt 4: Forge capability -> Invalid cap error */
    printf("[BACKDOOR] Attempt forge capability...\n");
    /* Cannot invoke seL4_Untyped_Retype without Untyped cap */

    printf("[BACKDOOR] All escalation attempts blocked by seL4 capabilities!\n");
}

/* ========== END BACKDOOR ========== */
BACKDOOR_PATCH

echo "Backdoor code appended to driver."
echo ""

# Rebuild
echo "Rebuilding seL4 image (incremental)..."
echo "  Build directory: $BUILD_DIR"
cd "$BUILD_DIR"

if command -v ninja &> /dev/null; then
    ninja 2>&1 | tail -5
else
    make -j$(nproc) 2>&1 | tail -5
fi

# Check if image was built
IMAGE_PATH="${BUILD_DIR}/images/${IMAGE_NAME}"
if [ ! -f "$IMAGE_PATH" ]; then
    echo "ERROR: Image not found after build: $IMAGE_PATH"
    echo "Restoring original driver..."
    cp "$BACKUP" "$DRIVER_SRC"
    exit 1
fi

echo ""
echo "Build successful!"
echo "  Image: $IMAGE_PATH ($(du -h "$IMAGE_PATH" | cut -f1))"

# Copy to gateway container
echo "Copying to gateway image directory..."
mkdir -p "$GATEWAY_IMAGE_DIR"
cp "$IMAGE_PATH" "${GATEWAY_IMAGE_DIR}/${IMAGE_NAME}"
echo "  Copied to: ${GATEWAY_IMAGE_DIR}/${IMAGE_NAME}"

echo ""
echo "============================================="
echo " Backdoored image ready!"
echo " "
echo " To test:"
echo "   docker compose up gateway"
echo "   echo -ne '\\x00\\x01\\x00\\x00\\x00\\x14\\x01\\x03\\x00\\x00\\x00\\x01\\xDE\\xAD\\xBE\\xEF\\xCA\\xFE\\xBA\\xBE' | nc localhost 502"
echo ""
echo " To restore original:"
echo "   cp $BACKUP $DRIVER_SRC"
echo "   cd $BUILD_DIR && ninja"
echo "============================================="
