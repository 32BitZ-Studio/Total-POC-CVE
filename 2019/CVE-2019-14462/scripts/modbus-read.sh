#!/bin/bash
#
# Simple Modbus TCP register reader using netcat
#
# Usage: ./modbus-read.sh [HOST] [PORT] [START_ADDR] [COUNT]
#
# Note: ASAN build (CVE-2022-0367) uses registers 100-109
#       Normal build (CVE-2019-14462) uses registers 0-9
#

HOST="${1:-127.0.0.1}"
PORT="${2:-5020}"
START_ADDR="${3:-100}"  # Default 100 for ASAN build
COUNT="${4:-10}"

# Convert to hex (big-endian)
START_HI=$(printf '%02x' $(( (START_ADDR >> 8) & 0xFF )))
START_LO=$(printf '%02x' $(( START_ADDR & 0xFF )))
COUNT_HI=$(printf '%02x' $(( (COUNT >> 8) & 0xFF )))
COUNT_LO=$(printf '%02x' $(( COUNT & 0xFF )))

# Modbus TCP: Read Holding Registers (Function 0x03)
# MBAP Header: TxID(2) + ProtoID(2) + Length(2) + UnitID(1)
# PDU: FuncCode(1) + StartAddr(2) + Quantity(2)
PACKET="\x00\x01\x00\x00\x00\x06\x01\x03\x${START_HI}\x${START_LO}\x${COUNT_HI}\x${COUNT_LO}"

echo "Modbus TCP Read Holding Registers"
echo "  Host: $HOST:$PORT"
echo "  Start Address: $START_ADDR"
echo "  Count: $COUNT"
echo ""
echo "Request:"
echo -ne "$PACKET" | xxd
echo ""
echo "Response:"
echo -ne "$PACKET" | nc -q 1 -w 2 "$HOST" "$PORT" | xxd
