#!/bin/bash
# Build standalone heating_controller with vulnerable libmodbus statically linked
# For debugging CVE-2022-0367 with GDB

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBMODBUS_DIR="$SCRIPT_DIR/libmodbus_vulnerable_0367"
BUILD_DIR="$SCRIPT_DIR/build_static"

echo "=== Building standalone heating_controller with CVE-2022-0367 ==="
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Step 1: Build libmodbus as static library
echo "[1/3] Building vulnerable libmodbus (static)..."
cd "$LIBMODBUS_DIR"

if [ ! -f configure ]; then
    ./autogen.sh
fi

./configure --prefix="$BUILD_DIR/libmodbus_install" \
    --enable-static \
    --disable-shared \
    CFLAGS="-g -O0"

make clean
make -j$(nproc)
make install

echo "     Static library: $BUILD_DIR/libmodbus_install/lib/libmodbus.a"
echo ""

# Step 2: Build heating_controller with static linking
echo "[2/3] Building heating_controller (static, debug, CVE-2022-0367)..."
cd "$SCRIPT_DIR"

gcc -g -O0 -Wall -Wextra -D_GNU_SOURCE -DCVE_2022_0367 -DSERVER_PORT=5020 \
    -I"$BUILD_DIR/libmodbus_install/include/modbus" \
    -o "$BUILD_DIR/heating_controller" \
    heating_controller.c process_sim.c display.c \
    "$BUILD_DIR/libmodbus_install/lib/libmodbus.a" \
    -lpthread -lm

echo "     Binary: $BUILD_DIR/heating_controller"
echo ""

# Step 3: Verify it's standalone
echo "[3/3] Verifying binary..."
if ldd "$BUILD_DIR/heating_controller" | grep -q libmodbus; then
    echo "     WARNING: Still dynamically linked to libmodbus!"
else
    echo "     OK: No external libmodbus dependency"
fi

echo ""
echo "=== Build complete ==="
echo ""
echo "To debug with GDB:"
echo "  cd $BUILD_DIR"
echo "  gdb ./heating_controller"
echo ""
echo "GDB commands to inspect the vulnerability:"
echo "  (gdb) break modbus_reply"
echo "  (gdb) run"
echo "  # Then from another terminal: ./cve_tools/cve_0367_attack 127.0.0.1 502"
echo "  (gdb) print mb_mapping->tab_registers"
echo "  (gdb) x/20xh mb_mapping->tab_registers - 50"
echo ""
