#!/bin/bash
#
# Simple Modbus TCP register writer using netcat
#
# Usage: ./modbus-write.sh <HOST> <PORT> <ADDR> <VALUE>
#
# Note: ASAN build (CVE-2022-0367) uses registers 100-109
#       Normal build (CVE-2019-14462) uses registers 0-9
#

if [ $# -lt 4 ]; then
    echo "Usage: $0 <HOST> <PORT> <ADDR> <VALUE>"
    echo ""
    echo "ASAN build (registers 100-109):"
    echo "  $0 127.0.0.1 5020 101 50   # Set valve to 50%"
    echo "  $0 127.0.0.1 5020 102 220  # Set setpoint to 22.0C"
    echo ""
    echo "Normal build (registers 0-9):"
    echo "  $0 127.0.0.1 5020 1 50     # Set valve to 50%"
    echo "  $0 127.0.0.1 5020 2 220    # Set setpoint to 22.0C"
    exit 1
fi

HOST="$1"
PORT="$2"
ADDR="$3"
VALUE="$4"

# Convert to hex (big-endian)
ADDR_HI=$(printf '%02x' $(( (ADDR >> 8) & 0xFF )))
ADDR_LO=$(printf '%02x' $(( ADDR & 0xFF )))
VALUE_HI=$(printf '%02x' $(( (VALUE >> 8) & 0xFF )))
VALUE_LO=$(printf '%02x' $(( VALUE & 0xFF )))

# Modbus TCP: Write Single Register (Function 0x06)
# MBAP Header: TxID(2) + ProtoID(2) + Length(2) + UnitID(1)
# PDU: FuncCode(1) + Addr(2) + Value(2)
PACKET="\x00\x01\x00\x00\x00\x06\x01\x06\x${ADDR_HI}\x${ADDR_LO}\x${VALUE_HI}\x${VALUE_LO}"

echo "Modbus TCP Write Single Register"
echo "  Host: $HOST:$PORT"
echo "  Address: $ADDR"
echo "  Value: $VALUE"
echo ""
echo "Request:"
echo -ne "$PACKET" | xxd
echo ""
echo "Response:"
echo -ne "$PACKET" | nc -q 1 -w 2 "$HOST" "$PORT" | xxd
