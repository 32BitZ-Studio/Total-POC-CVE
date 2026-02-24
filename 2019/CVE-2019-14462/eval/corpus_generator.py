#!/usr/bin/env python3
"""
Modbus Test Corpus Generator

Generates 1050+ packets for E1 structural validation testing across four categories:
- Valid packets (200): Legitimate Modbus operations
- Malformed packets (500): Structural violations of the Modbus specification
- Attack variants (150): CVE exploit pattern variations
- Fuzz-generated (200): Randomized malformed packets

Output structure:
  eval/corpus/
    ├── valid/           # Legitimate packets
    ├── malformed/       # Structural violations
    ├── attacks/         # CVE variants
    ├── fuzz/            # Random malformed
    └── manifest.json   # Metadata for each packet

For defensive security research only.
"""

import json
import os
import random
import struct
import sys
from pathlib import Path

# Seed for reproducibility
random.seed(42)

CORPUS_DIR = Path(__file__).parent / "corpus"

# Modbus function codes
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_COILS = 0x0F
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_WRITE_FILE_RECORD = 0x15
FC_READ_WRITE_MULTIPLE = 0x17

VALID_FUNCTION_CODES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x2B]


def build_mbap(transaction_id, protocol_id, length, unit_id):
    """Build MBAP header (7 bytes)."""
    return struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)


def build_modbus_request(transaction_id, unit_id, function_code, data):
    """Build a complete Modbus TCP request with correct MBAP header."""
    pdu = bytes([function_code]) + data
    length = len(pdu) + 1  # +1 for unit_id
    mbap = build_mbap(transaction_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_raw_packet(transaction_id, protocol_id, length, unit_id, pdu_bytes):
    """Build a raw packet with explicit header fields (for malformed packets)."""
    mbap = build_mbap(transaction_id, protocol_id, length, unit_id)
    return mbap + pdu_bytes


# ===========================================================================
# Valid Packet Generators
# ===========================================================================

def gen_valid_packets():
    """Generate ~200 legitimate Modbus operations."""
    packets = []
    tid = 1

    # FC01: Read Coils - various quantities
    for qty in [1, 8, 16, 100, 500, 1000, 2000]:
        for addr in [0x0000, 0x0010, 0x00FF, 0x7FFF]:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_COILS, data)
            packets.append(("valid", f"fc01_addr{addr:#06x}_qty{qty}", pkt,
                           {"function": "read_coils", "address": addr, "quantity": qty}))
            tid += 1

    # FC02: Read Discrete Inputs
    for qty in [1, 10, 100, 500, 1000, 2000]:
        for addr in [0x0000, 0x0100, 0x1000, 0x7FFF]:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_DISCRETE_INPUTS, data)
            packets.append(("valid", f"fc02_addr{addr:#06x}_qty{qty}", pkt,
                           {"function": "read_discrete_inputs", "address": addr, "quantity": qty}))
            tid += 1

    # FC03: Read Holding Registers - various quantities and addresses
    for qty in [1, 10, 50, 100, 125]:
        for addr in [0x0000, 0x0001, 0x0009, 0x0064, 0x7F00]:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
            packets.append(("valid", f"fc03_addr{addr:#06x}_qty{qty}", pkt,
                           {"function": "read_holding_regs", "address": addr, "quantity": qty}))
            tid += 1

    # FC04: Read Input Registers
    for qty in [1, 10, 50, 100, 125]:
        for addr in [0x0000, 0x0050, 0x0100, 0x7F00]:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_INPUT_REGISTERS, data)
            packets.append(("valid", f"fc04_addr{addr:#06x}_qty{qty}", pkt,
                           {"function": "read_input_regs", "address": addr, "quantity": qty}))
            tid += 1

    # FC05: Write Single Coil
    for addr in [0x0000, 0x0001, 0x00FF, 0x7FFF]:
        for val in [0xFF00, 0x0000]:  # ON and OFF
            data = struct.pack(">HH", addr, val)
            pkt = build_modbus_request(tid, 0x01, FC_WRITE_SINGLE_COIL, data)
            packets.append(("valid", f"fc05_addr{addr:#06x}_val{val:#06x}", pkt,
                           {"function": "write_single_coil", "address": addr, "value": val}))
            tid += 1

    # FC06: Write Single Register
    for addr in [0x0000, 0x0001, 0x0009]:
        for val in [0x0000, 0x0001, 0x00FF, 0x7FFF, 0xFFFF]:
            data = struct.pack(">HH", addr, val)
            pkt = build_modbus_request(tid, 0x01, FC_WRITE_SINGLE_REGISTER, data)
            packets.append(("valid", f"fc06_addr{addr:#06x}_val{val:#06x}", pkt,
                           {"function": "write_single_reg", "address": addr, "value": val}))
            tid += 1

    # FC0F: Write Multiple Coils
    for qty in [1, 8, 16, 100]:
        byte_count = (qty + 7) // 8
        coil_data = bytes([0xFF] * byte_count)
        addr = 0x0000
        data = struct.pack(">HHB", addr, qty, byte_count) + coil_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
        packets.append(("valid", f"fc0f_qty{qty}", pkt,
                       {"function": "write_multiple_coils", "address": addr, "quantity": qty}))
        tid += 1

    # FC10: Write Multiple Registers
    for qty in [1, 5, 10, 50, 123]:
        byte_count = qty * 2
        reg_data = struct.pack(">" + "H" * qty, *[i for i in range(qty)])
        addr = 0x0000
        data = struct.pack(">HHB", addr, qty, byte_count) + reg_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
        packets.append(("valid", f"fc10_qty{qty}", pkt,
                       {"function": "write_multiple_regs", "address": addr, "quantity": qty}))
        tid += 1

    # Various unit IDs (valid range)
    for uid in [0x01, 0x02, 0x10, 0x7F, 0xFE]:
        data = struct.pack(">HH", 0x0000, 0x0001)
        pkt = build_modbus_request(tid, uid, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("valid", f"fc03_uid{uid:#04x}", pkt,
                       {"function": "read_holding_regs", "unit_id": uid}))
        tid += 1

    # Broadcast (unit_id 0x00) and max (0xFF)
    for uid in [0x00, 0xFF]:
        data = struct.pack(">HH", 0x0000, 0x0001)
        pkt = build_modbus_request(tid, uid, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("valid", f"fc03_uid{uid:#04x}_broadcast", pkt,
                       {"function": "read_holding_regs", "unit_id": uid, "note": "broadcast" if uid == 0 else "max_uid"}))
        tid += 1

    # FC17: Read/Write Multiple Registers
    for read_qty in [1, 10, 50, 125]:
        for write_qty in [1, 5, 10]:
            byte_count = write_qty * 2
            write_data = struct.pack(">" + "H" * write_qty, *range(write_qty))
            data = struct.pack(">HHHHB", 0x0000, read_qty, 0x0010, write_qty, byte_count) + write_data
            pkt = build_modbus_request(tid, 0x01, FC_READ_WRITE_MULTIPLE, data)
            packets.append(("valid", f"fc17_r{read_qty}_w{write_qty}", pkt,
                           {"function": "read_write_multiple", "read_qty": read_qty, "write_qty": write_qty}))
            tid += 1

    # Various transaction IDs (all valid)
    for txid in [0x0000, 0x0001, 0x00FF, 0x0100, 0x1234, 0x7FFF, 0x8000, 0xAAAA, 0xFFFE, 0xFFFF]:
        data = struct.pack(">HH", 0x0000, 0x0001)
        pkt = build_modbus_request(txid, 0x01, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("valid", f"fc03_txid{txid:#06x}", pkt,
                       {"function": "read_holding_regs", "transaction_id": txid}))

    # Edge case addresses for FC06
    for addr in [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]:
        data = struct.pack(">HH", addr, 100)
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_SINGLE_REGISTER, data)
        packets.append(("valid", f"fc06_edge_addr{addr:#06x}", pkt,
                       {"function": "write_single_reg", "address": addr, "value": 100}))
        tid += 1

    # Max-quantity boundary cases (exactly at limit)
    data = struct.pack(">HH", 0x0000, 2000)
    pkt = build_modbus_request(tid, 0x01, FC_READ_COILS, data)
    packets.append(("valid", "fc01_max_qty_2000", pkt,
                   {"function": "read_coils", "quantity": 2000, "note": "max allowed"}))
    tid += 1

    data = struct.pack(">HH", 0x0000, 125)
    pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
    packets.append(("valid", "fc03_max_qty_125", pkt,
                   {"function": "read_holding_regs", "quantity": 125, "note": "max allowed"}))
    tid += 1

    # FC0F boundary: exactly 1968 coils (max)
    qty = 1968
    byte_count = (qty + 7) // 8
    coil_data = bytes([0xAA] * byte_count)
    data = struct.pack(">HHB", 0, qty, byte_count) + coil_data
    pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
    packets.append(("valid", "fc0f_max_qty_1968", pkt,
                   {"function": "write_multiple_coils", "quantity": qty, "note": "max allowed"}))
    tid += 1

    # FC10 boundary: exactly 123 registers (max)
    qty = 123
    byte_count = qty * 2
    reg_data = struct.pack(">" + "H" * qty, *range(qty))
    data = struct.pack(">HHB", 0, qty, byte_count) + reg_data
    pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
    packets.append(("valid", "fc10_max_qty_123", pkt,
                   {"function": "write_multiple_regs", "quantity": qty, "note": "max allowed"}))
    tid += 1

    # Address boundary: addr + qty exactly = 0xFFFF (not overflow)
    for fc, max_qty in [(FC_READ_COILS, 2000), (FC_READ_HOLDING_REGISTERS, 125)]:
        addr = 0xFFFF - max_qty
        data = struct.pack(">HH", addr, max_qty)
        pkt = build_modbus_request(tid, 0x01, fc, data)
        packets.append(("valid", f"fc{fc:#04x}_boundary_addr_plus_qty_ffff", pkt,
                       {"function": f"fc{fc:#04x}", "address": addr, "quantity": max_qty,
                        "note": "addr+qty exactly 0xFFFF"}))
        tid += 1

    return packets


# ===========================================================================
# Malformed Packet Generators (Structural Violations)
# ===========================================================================

def gen_malformed_mbap_length():
    """MBAP header length field violations."""
    packets = []
    tid = 1000

    # Length < actual payload (CVE-2019-14462 pattern)
    pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
    for declared in [1, 2, 3, 4, 5]:  # Actual PDU+UnitID = 6
        pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
        packets.append(("malformed", f"mbap_len_under_{declared}", pkt,
                       {"violation": "mbap_length_under", "declared": declared, "actual": 6}))
        tid += 1

    # Length much smaller than payload (large deltas)
    large_pdu = bytes([FC_WRITE_MULTIPLE_REGISTERS]) + struct.pack(">HHB", 0, 50, 100) + bytes(100)
    for declared in [5, 10, 20, 50, 60]:
        pkt = build_raw_packet(tid, 0x0000, declared, 0x01, large_pdu)
        packets.append(("malformed", f"mbap_len_under_large_{declared}", pkt,
                       {"violation": "mbap_length_under", "declared": declared, "actual": len(large_pdu) + 1}))
        tid += 1

    # Length > actual payload
    pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
    for declared in [10, 20, 50, 100, 200, 255, 500, 1000, 5000, 10000]:
        pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
        packets.append(("malformed", f"mbap_len_over_{declared}", pkt,
                       {"violation": "mbap_length_over", "declared": declared, "actual": 6}))
        tid += 1

    # Additional under-declared with various deltas
    for delta in range(1, 46):
        base_size = 6
        declared = max(1, base_size - delta)
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
        if declared < base_size:
            pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
            packets.append(("malformed", f"mbap_len_delta_under_{delta}", pkt,
                           {"violation": "mbap_length_under", "delta": delta}))
            tid += 1

    # Additional over-declared with various deltas
    for delta in [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 10000, 30000, 65000]:
        base_size = 6
        declared = base_size + delta
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
        pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
        packets.append(("malformed", f"mbap_len_delta_over_{delta}", pkt,
                       {"violation": "mbap_length_over", "delta": delta}))
        tid += 1

    # Length = 0
    for fc in [FC_READ_COILS, FC_READ_HOLDING_REGISTERS, FC_WRITE_SINGLE_COIL]:
        pdu = bytes([fc]) + struct.pack(">HH", 0, 1)
        pkt = build_raw_packet(tid, 0x0000, 0, 0x01, pdu)
        packets.append(("malformed", f"mbap_len_zero_fc{fc:#04x}", pkt,
                       {"violation": "mbap_length_zero", "function": fc}))
        tid += 1

    # Length = 0xFFFF (maximum)
    pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
    pkt = build_raw_packet(tid, 0x0000, 0xFFFF, 0x01, pdu)
    packets.append(("malformed", "mbap_len_max", pkt,
                   {"violation": "mbap_length_max", "declared": 0xFFFF}))
    tid += 1

    return packets


def gen_malformed_protocol_id():
    """Protocol ID != 0 violations."""
    packets = []
    tid = 2000

    pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
    for proto_id in [0x0001, 0x0002, 0x000A, 0x00FF, 0x0100, 0x1234, 0x7FFF, 0x8000,
                     0xAAAA, 0xDEAD, 0xBEEF, 0xCAFE, 0xFACE, 0xFEED, 0xFFFF,
                     0x0003, 0x0004, 0x0005, 0x0010, 0x0080]:
        pkt = build_raw_packet(tid, proto_id, 6, 0x01, pdu)
        packets.append(("malformed", f"proto_id_{proto_id:#06x}", pkt,
                       {"violation": "protocol_id_nonzero", "protocol_id": proto_id}))
        tid += 1

    return packets


def gen_malformed_function_codes():
    """Invalid/reserved function code violations."""
    packets = []
    tid = 3000

    # Reserved codes
    reserved = [0x00, 0x09, 0x0A, 0x0D, 0x0E, 0x12, 0x13, 0x18, 0x19, 0x1A,
                0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
                0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2C, 0x2D, 0x2E, 0x2F]
    for fc in reserved:
        data = struct.pack(">HH", 0, 1)
        pdu = bytes([fc]) + data
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"fc_reserved_{fc:#04x}", pkt,
                       {"violation": "reserved_function_code", "function_code": fc}))
        tid += 1

    # Exception response codes (0x80+) sent as requests
    for fc in [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x8F, 0x90, 0x95,
               0x97, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFE, 0xFF,
               0x91, 0x92, 0x93, 0x94, 0x96, 0x98, 0x99, 0x9A, 0x9B, 0x9C]:
        data = bytes([0x01])  # Exception code
        pdu = bytes([fc]) + data
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"fc_exception_{fc:#04x}", pkt,
                       {"violation": "exception_code_as_request", "function_code": fc}))
        tid += 1

    return packets


def gen_malformed_fc01():
    """FC01 Read Coils - quantity violations."""
    packets = []
    tid = 4000

    # Quantity = 0
    for addr in [0x0000, 0x0001, 0x00FF, 0x7FFF, 0xFFFF]:
        data = struct.pack(">HH", addr, 0)
        pkt = build_modbus_request(tid, 0x01, FC_READ_COILS, data)
        packets.append(("malformed", f"fc01_qty0_addr{addr:#06x}", pkt,
                       {"violation": "fc01_quantity_zero", "address": addr}))
        tid += 1

    # Quantity > 2000 (max allowed)
    for qty in [2001, 2048, 3000, 4000, 5000, 10000, 20000, 32000, 50000, 65535]:
        data = struct.pack(">HH", 0, qty)
        pkt = build_modbus_request(tid, 0x01, FC_READ_COILS, data)
        packets.append(("malformed", f"fc01_qty_over_{qty}", pkt,
                       {"violation": "fc01_quantity_over", "quantity": qty}))
        tid += 1

    # Address + Quantity overflow (> 0xFFFF)
    overflow_pairs = [(0xFFFF, 1), (0xFFFE, 3), (0xFF00, 256), (0xF000, 4097),
                      (0x8000, 0x8001), (0xFFF0, 20), (0xFFFC, 5), (0xFFF8, 10),
                      (0xFE00, 600), (0xF800, 2100), (0xFFFF, 2000), (0xFFF0, 2000),
                      (0xFF00, 2000), (0xF000, 5000), (0xE000, 10000),
                      (0xC000, 20000), (0x8001, 32768), (0x7FFF, 32770),
                      (0xFFFE, 2), (0xFFFD, 4)]
    for addr, qty in overflow_pairs:
        if addr + qty > 0xFFFF:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_COILS, data)
            packets.append(("malformed", f"fc01_overflow_a{addr:#06x}_q{qty}", pkt,
                           {"violation": "fc01_address_overflow", "address": addr, "quantity": qty}))
            tid += 1

    return packets


def gen_malformed_fc03():
    """FC03 Read Holding Registers - quantity violations."""
    packets = []
    tid = 5000

    # Quantity = 0
    for addr in [0x0000, 0x0001, 0x00FF, 0x7FFF, 0xFFFF]:
        data = struct.pack(">HH", addr, 0)
        pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("malformed", f"fc03_qty0_addr{addr:#06x}", pkt,
                       {"violation": "fc03_quantity_zero", "address": addr}))
        tid += 1

    # Quantity > 125 (max for FC03)
    for qty in [126, 127, 128, 150, 200, 255, 256, 500, 1000, 5000, 10000, 30000, 65535]:
        data = struct.pack(">HH", 0, qty)
        pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("malformed", f"fc03_qty_over_{qty}", pkt,
                       {"violation": "fc03_quantity_over", "quantity": qty}))
        tid += 1

    # Address + Quantity overflow
    for addr, qty in [(0xFFFF, 1), (0xFFFE, 2), (0xFF82, 125), (0xFF00, 125),
                       (0xF000, 125), (0xFFFF, 125), (0xFFF0, 125),
                       (0xFF80, 130), (0xFF00, 256), (0xF000, 5000),
                       (0x8000, 32768), (0xFFFD, 4), (0xFFFC, 5),
                       (0xFFF0, 20), (0xFFE0, 50), (0xFFC0, 100),
                       (0xFF00, 300), (0xFE00, 600), (0xFC00, 1100),
                       (0xF000, 5000), (0xE000, 10000)]:
        if addr + qty > 0xFFFF:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
            packets.append(("malformed", f"fc03_overflow_a{addr:#06x}_q{qty}", pkt,
                           {"violation": "fc03_address_overflow", "address": addr, "quantity": qty}))
            tid += 1

    return packets


def gen_malformed_fc05():
    """FC05 Write Single Coil - invalid values."""
    packets = []
    tid = 6000

    # Value != 0x0000 and != 0xFF00
    invalid_values = [0x0001, 0x0002, 0x000F, 0x00FF, 0x0100, 0x0F00, 0x1000,
                      0x1234, 0x5678, 0x7F00, 0x7FFF, 0x8000, 0x8001, 0xAAAA,
                      0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE, 0xFE00, 0xFEFF, 0xFF01,
                      0xFF7F, 0xFFFE, 0xFFFF, 0xDEAD, 0xBEEF, 0xCAFE, 0xFACE,
                      0x1111, 0x2222]
    for val in invalid_values:
        data = struct.pack(">HH", 0x0000, val)
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_SINGLE_COIL, data)
        packets.append(("malformed", f"fc05_invalid_val_{val:#06x}", pkt,
                       {"violation": "fc05_invalid_value", "value": val}))
        tid += 1

    return packets


def gen_malformed_fc0f():
    """FC0F Write Multiple Coils - byte count mismatches."""
    packets = []
    tid = 7000

    # Byte count too few
    for qty in [8, 16, 32, 64, 100]:
        correct_bytes = (qty + 7) // 8
        for fewer in range(1, min(correct_bytes, 5)):
            byte_count = correct_bytes - fewer
            coil_data = bytes([0xFF] * byte_count)
            data = struct.pack(">HHB", 0, qty, byte_count) + coil_data
            pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
            packets.append(("malformed", f"fc0f_bytes_under_q{qty}_b{byte_count}", pkt,
                           {"violation": "fc0f_byte_count_under", "quantity": qty,
                            "byte_count": byte_count, "expected": correct_bytes}))
            tid += 1

    # Byte count too many
    for qty in [8, 16, 32, 64, 100]:
        correct_bytes = (qty + 7) // 8
        for more in [1, 2, 5, 10]:
            byte_count = correct_bytes + more
            coil_data = bytes([0xFF] * byte_count)
            data = struct.pack(">HHB", 0, qty, byte_count) + coil_data
            pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
            packets.append(("malformed", f"fc0f_bytes_over_q{qty}_b{byte_count}", pkt,
                           {"violation": "fc0f_byte_count_over", "quantity": qty,
                            "byte_count": byte_count, "expected": correct_bytes}))
            tid += 1

    # Quantity = 0 but byte_count > 0
    for byte_count in [1, 2, 5]:
        coil_data = bytes([0xFF] * byte_count)
        data = struct.pack(">HHB", 0, 0, byte_count) + coil_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
        packets.append(("malformed", f"fc0f_qty0_bytes{byte_count}", pkt,
                       {"violation": "fc0f_quantity_zero_with_data", "byte_count": byte_count}))
        tid += 1

    return packets


def gen_malformed_fc10():
    """FC10 Write Multiple Registers - byte count mismatches."""
    packets = []
    tid = 8000

    # Byte count too few
    for qty in [2, 5, 10, 20, 50]:
        correct_bytes = qty * 2
        for fewer in [1, 2, 4, 10]:
            byte_count = max(1, correct_bytes - fewer)
            if byte_count < correct_bytes:
                reg_data = bytes([0x00] * byte_count)
                data = struct.pack(">HHB", 0, qty, byte_count) + reg_data
                pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
                packets.append(("malformed", f"fc10_bytes_under_q{qty}_b{byte_count}", pkt,
                               {"violation": "fc10_byte_count_under", "quantity": qty,
                                "byte_count": byte_count, "expected": correct_bytes}))
                tid += 1

    # Byte count too many
    for qty in [2, 5, 10, 20, 50]:
        correct_bytes = qty * 2
        for more in [1, 2, 4, 10, 20]:
            byte_count = correct_bytes + more
            reg_data = bytes([0x00] * byte_count)
            data = struct.pack(">HHB", 0, qty, byte_count) + reg_data
            pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
            packets.append(("malformed", f"fc10_bytes_over_q{qty}_b{byte_count}", pkt,
                           {"violation": "fc10_byte_count_over", "quantity": qty,
                            "byte_count": byte_count, "expected": correct_bytes}))
            tid += 1

    # Quantity > 123 (max for FC10)
    for qty in [124, 125, 126, 150, 200, 255]:
        byte_count = min(qty * 2, 250)
        reg_data = bytes([0x00] * byte_count)
        data = struct.pack(">HHB", 0, qty, byte_count) + reg_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
        packets.append(("malformed", f"fc10_qty_over_{qty}", pkt,
                       {"violation": "fc10_quantity_over", "quantity": qty}))
        tid += 1

    return packets


def gen_malformed_cross_field():
    """Cross-field consistency violations."""
    packets = []
    tid = 9000

    # PDU length vs function constraints (too short for function)
    # FC03 requires exactly 4 bytes of data, send fewer
    for short_len in [0, 1, 2, 3]:
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + bytes(short_len)
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"pdu_too_short_fc03_{short_len}b", pkt,
                       {"violation": "pdu_too_short", "function": 3, "pdu_data_len": short_len}))
        tid += 1

    # FC05 requires exactly 4 bytes of data
    for short_len in [0, 1, 2, 3]:
        pdu = bytes([FC_WRITE_SINGLE_COIL]) + bytes(short_len)
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"pdu_too_short_fc05_{short_len}b", pkt,
                       {"violation": "pdu_too_short", "function": 5, "pdu_data_len": short_len}))
        tid += 1

    # FC10 requires at least 5 bytes header + data
    for short_len in [0, 1, 2, 3, 4]:
        pdu = bytes([FC_WRITE_MULTIPLE_REGISTERS]) + bytes(short_len)
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"pdu_too_short_fc10_{short_len}b", pkt,
                       {"violation": "pdu_too_short", "function": 16, "pdu_data_len": short_len}))
        tid += 1

    # PDU too long for function (extra trailing bytes)
    for extra in [1, 2, 5, 10, 50, 100]:
        data = struct.pack(">HH", 0, 1) + bytes(extra)
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + data
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"pdu_too_long_fc03_{extra}extra", pkt,
                       {"violation": "pdu_too_long", "function": 3, "extra_bytes": extra}))
        tid += 1

    # Empty PDU (no function code)
    pkt = build_raw_packet(tid, 0x0000, 1, 0x01, b"")
    packets.append(("malformed", "empty_pdu", pkt,
                   {"violation": "empty_pdu"}))
    tid += 1

    # Very large PDU
    for size in [253, 260, 500, 1000]:
        large_pdu = bytes([FC_READ_HOLDING_REGISTERS]) + bytes(size)
        pkt = build_raw_packet(tid, 0x0000, len(large_pdu) + 1, 0x01, large_pdu)
        packets.append(("malformed", f"oversized_pdu_{size}", pkt,
                       {"violation": "oversized_pdu", "size": size}))
        tid += 1

    # FC01 Quantity = 0 + various function codes
    for fc in [FC_READ_DISCRETE_INPUTS, FC_READ_INPUT_REGISTERS]:
        for addr in [0x0000, 0x0100, 0xFFFF]:
            data = struct.pack(">HH", addr, 0)
            pkt = build_modbus_request(tid, 0x01, fc, data)
            packets.append(("malformed", f"fc{fc:#04x}_qty0_addr{addr:#06x}", pkt,
                           {"violation": f"fc{fc:#04x}_quantity_zero", "address": addr}))
            tid += 1

    # FC04 quantity > 125
    for qty in [126, 200, 500, 1000, 65535]:
        data = struct.pack(">HH", 0, qty)
        pkt = build_modbus_request(tid, 0x01, FC_READ_INPUT_REGISTERS, data)
        packets.append(("malformed", f"fc04_qty_over_{qty}", pkt,
                       {"violation": "fc04_quantity_over", "quantity": qty}))
        tid += 1

    # FC02 quantity > 2000
    for qty in [2001, 5000, 10000, 65535]:
        data = struct.pack(">HH", 0, qty)
        pkt = build_modbus_request(tid, 0x01, FC_READ_DISCRETE_INPUTS, data)
        packets.append(("malformed", f"fc02_qty_over_{qty}", pkt,
                       {"violation": "fc02_quantity_over", "quantity": qty}))
        tid += 1

    # FC0F quantity > 1968 (max for write multiple coils)
    for qty in [1969, 2000, 5000, 10000]:
        byte_count = min((qty + 7) // 8, 246)
        coil_data = bytes([0xFF] * byte_count)
        data = struct.pack(">HHB", 0, qty, byte_count) + coil_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
        packets.append(("malformed", f"fc0f_qty_over_{qty}", pkt,
                       {"violation": "fc0f_quantity_over", "quantity": qty}))
        tid += 1

    # MBAP length field = 1 (only unit_id, no PDU)
    for fc in [FC_READ_COILS, FC_READ_HOLDING_REGISTERS, FC_WRITE_SINGLE_REGISTER]:
        pdu = bytes([fc]) + struct.pack(">HH", 0, 1)
        pkt = build_raw_packet(tid, 0x0000, 1, 0x01, pdu)
        packets.append(("malformed", f"mbap_len_1_fc{fc:#04x}", pkt,
                       {"violation": "mbap_length_1_with_pdu", "function": fc}))
        tid += 1

    # FC10: byte_count = 0 with qty > 0
    for qty in [1, 5, 10, 50, 100]:
        data = struct.pack(">HHB", 0, qty, 0)
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
        packets.append(("malformed", f"fc10_bytecnt0_qty{qty}", pkt,
                       {"violation": "fc10_byte_count_zero", "quantity": qty}))
        tid += 1

    # FC10: byte_count odd (should always be even for registers)
    for qty in [1, 5, 10]:
        byte_count = qty * 2 + 1  # Odd
        reg_data = bytes([0x00] * byte_count)
        data = struct.pack(">HHB", 0, qty, byte_count) + reg_data
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_REGISTERS, data)
        packets.append(("malformed", f"fc10_odd_bytecnt_q{qty}", pkt,
                       {"violation": "fc10_odd_byte_count", "quantity": qty, "byte_count": byte_count}))
        tid += 1

    # FC0F: byte_count = 0 with qty > 0
    for qty in [1, 8, 16, 100, 1000]:
        data = struct.pack(">HHB", 0, qty, 0)
        pkt = build_modbus_request(tid, 0x01, FC_WRITE_MULTIPLE_COILS, data)
        packets.append(("malformed", f"fc0f_bytecnt0_qty{qty}", pkt,
                       {"violation": "fc0f_byte_count_zero", "quantity": qty}))
        tid += 1

    # Multiple violations combined: bad protocol + bad length + bad FC
    for proto in [0x0001, 0xFFFF]:
        for length_delta in [-3, 100]:
            for fc in [0x00, 0x80]:
                pdu = bytes([fc]) + struct.pack(">HH", 0, 1)
                actual_len = len(pdu) + 1
                declared = max(1, actual_len + length_delta)
                pkt = build_raw_packet(tid, proto, declared, 0x01, pdu)
                packets.append(("malformed", f"multi_violation_p{proto:#06x}_d{length_delta}_fc{fc:#04x}", pkt,
                               {"violation": "multiple_violations", "protocol_id": proto,
                                "length_delta": length_delta, "function_code": fc}))
                tid += 1

    # FC03 with extra data appended after proper request
    for extra in [1, 2, 4, 8, 16, 32, 64, 128, 200]:
        data = struct.pack(">HH", 0, 1) + bytes([0xAA] * extra)
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + data
        # Correct MBAP length for the full packet (including extra)
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"fc03_trailing_{extra}b", pkt,
                       {"violation": "trailing_data", "function": 3, "extra_bytes": extra}))
        tid += 1

    # FC05 Write Single Coil with trailing data
    for extra in [1, 2, 4, 10]:
        data = struct.pack(">HH", 0, 0xFF00) + bytes(extra)
        pdu = bytes([FC_WRITE_SINGLE_COIL]) + data
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("malformed", f"fc05_trailing_{extra}b", pkt,
                       {"violation": "trailing_data", "function": 5, "extra_bytes": extra}))
        tid += 1

    # Address overflow for FC02 (Read Discrete Inputs)
    for addr, qty in [(0xFFFF, 1), (0xFFFE, 3), (0xFF00, 256), (0xF000, 4097),
                       (0xFFFF, 2000), (0xFFF0, 2000)]:
        if addr + qty > 0xFFFF:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_DISCRETE_INPUTS, data)
            packets.append(("malformed", f"fc02_overflow_a{addr:#06x}_q{qty}", pkt,
                           {"violation": "fc02_address_overflow", "address": addr, "quantity": qty}))
            tid += 1

    # Address overflow for FC04 (Read Input Registers)
    for addr, qty in [(0xFFFF, 1), (0xFFFE, 2), (0xFF82, 125), (0xFFFF, 125)]:
        if addr + qty > 0xFFFF:
            data = struct.pack(">HH", addr, qty)
            pkt = build_modbus_request(tid, 0x01, FC_READ_INPUT_REGISTERS, data)
            packets.append(("malformed", f"fc04_overflow_a{addr:#06x}_q{qty}", pkt,
                           {"violation": "fc04_address_overflow", "address": addr, "quantity": qty}))
            tid += 1

    return packets


# ===========================================================================
# CVE Attack Variant Generators
# ===========================================================================

def gen_cve_14462_variants():
    """CVE-2019-14462: MBAP length < payload (heap buffer overflow variants)."""
    packets = []
    tid = 10000

    # Classic pattern: small declared length, large actual payload
    for declared in [5, 10, 20, 30, 40, 50, 60]:
        for payload_size in [100, 200, 300, 400, 500, 601]:
            if declared < payload_size:
                pdu = bytes([FC_READ_HOLDING_REGISTERS]) + bytes(payload_size - 1)
                pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
                packets.append(("attacks", f"cve14462_decl{declared}_actual{payload_size}", pkt,
                               {"cve": "CVE-2019-14462", "declared_length": declared,
                                "actual_payload": payload_size, "overflow_bytes": payload_size - declared}))
                tid += 1

    # Additional edge cases: minimal overflow
    for overflow in [1, 2, 3, 5, 10, 50, 100, 200]:
        declared = 6  # Minimum valid
        payload_size = declared + overflow
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + bytes(payload_size - 1)
        pkt = build_raw_packet(tid, 0x0000, declared, 0x01, pdu)
        packets.append(("attacks", f"cve14462_overflow{overflow}b", pkt,
                       {"cve": "CVE-2019-14462", "declared_length": declared,
                        "actual_payload": payload_size, "overflow_bytes": overflow}))
        tid += 1

    return packets[:50]


def gen_cve_0367_variants():
    """CVE-2022-0367: Invalid register mapping exploits."""
    packets = []
    tid = 11000

    # Access registers at addresses that trigger start_address bugs
    invalid_addrs = [99, 98, 97, 50, 0, 110, 111, 200, 255, 500,
                     1000, 5000, 10000, 32767, 65534, 65535,
                     101, 102, 103, 104, 105, 106, 107, 108, 109,
                     150, 250, 1024, 2048, 4096, 8192, 16384, 32768]
    for addr in invalid_addrs[:30]:
        data = struct.pack(">HH", addr, 1)
        pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS, data)
        packets.append(("attacks", f"cve0367_addr{addr}", pkt,
                       {"cve": "CVE-2022-0367", "address": addr,
                        "note": "heap underflow if start_registers=100"}))
        tid += 1

    return packets


def gen_cve_20685_variants():
    """CVE-2022-20685: Snort Modbus preprocessor integer overflow."""
    packets = []
    tid = 12000

    # The exact exploit: FC 0x15 (Write File Record) with crafted record lengths
    # that cause uint16_t overflow in bytes_processed counter
    base_payload = bytearray(14)
    base_payload[0] = 0x06   # ref_type (required for validation)
    # Offset 5-6: record_length for first read = 0xFFFE
    base_payload[5] = 0xFF
    base_payload[6] = 0xFE
    # Offset 8-9: record_length for second read = 0xFFFB
    base_payload[8] = 0xFF
    base_payload[9] = 0xFB

    # Standard attack packet
    pdu = bytes([FC_WRITE_FILE_RECORD]) + bytes([len(base_payload)]) + bytes(base_payload)
    pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
    packets.append(("attacks", "cve20685_standard", pkt,
                   {"cve": "CVE-2022-20685", "variant": "standard",
                    "record_length_1": 0xFFFE, "record_length_2": 0xFFFB}))
    tid += 1

    # Variants with different record_length pairs that also overflow
    overflow_pairs = [
        (0xFFFE, 0xFFFB),  # Standard: 0→3→0 loop
        (0xFFFC, 0xFFF9),  # 0→5→0 variant
        (0xFFFA, 0xFFF7),  # 0→7→0 variant
        (0xFFF8, 0xFFF5),  # 0→9→0 variant
        (0xFFF0, 0xFFED),  # 0→17→0 variant
        (0xFFFF, 0xFFFC),  # 0→1→0 variant (tightest)
        (0xFFFD, 0xFFFA),  # 0→4→0 variant
        (0xFFFB, 0xFFF8),  # 0→6→0 variant
        (0xFFF9, 0xFFF6),  # 0→8→0 variant
        (0xFFF5, 0xFFF2),  # 0→11→0 variant
    ]
    for rl1, rl2 in overflow_pairs:
        payload = bytearray(14)
        payload[0] = 0x06
        payload[5] = (rl1 >> 8) & 0xFF
        payload[6] = rl1 & 0xFF
        payload[8] = (rl2 >> 8) & 0xFF
        payload[9] = rl2 & 0xFF

        pdu = bytes([FC_WRITE_FILE_RECORD]) + bytes([len(payload)]) + bytes(payload)
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("attacks", f"cve20685_rl1_{rl1:#06x}_rl2_{rl2:#06x}", pkt,
                       {"cve": "CVE-2022-20685", "variant": "overflow_pair",
                        "record_length_1": rl1, "record_length_2": rl2}))
        tid += 1

    # Variants with different data_length byte
    for data_len in [10, 14, 20, 30, 50, 100, 200, 250]:
        payload = bytearray(max(14, data_len))
        payload[0] = 0x06
        payload[5] = 0xFF
        payload[6] = 0xFE
        if len(payload) > 8:
            payload[8] = 0xFF
            payload[9] = 0xFB

        pdu = bytes([FC_WRITE_FILE_RECORD]) + bytes([min(data_len, 250)]) + bytes(payload[:data_len])
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("attacks", f"cve20685_datalen_{data_len}", pkt,
                       {"cve": "CVE-2022-20685", "variant": "data_length",
                        "data_length": data_len}))
        tid += 1

    return packets[:20]


def gen_tcp_segmentation_variants():
    """TCP segmentation evasion: split MBAP header across segments."""
    packets = []
    tid = 13000

    # These represent the full packets that would be sent as split TCP segments
    # The split points are recorded in metadata for the test runner
    full_packet = build_modbus_request(1, 0x01, FC_READ_HOLDING_REGISTERS,
                                        struct.pack(">HH", 0, 1))

    # Split at various points within the MBAP header
    for split_point in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        if split_point < len(full_packet):
            packets.append(("attacks", f"tcp_seg_split_{split_point}", full_packet,
                           {"cve": "tcp_segmentation", "split_point": split_point,
                            "segment_1_len": split_point,
                            "segment_2_len": len(full_packet) - split_point,
                            "note": "send as two TCP segments"}))
            tid += 1

    # Multiple splits (3+ segments)
    for splits in [(2, 5), (3, 7), (1, 4), (2, 6), (4, 8), (1, 3), (2, 4),
                   (3, 6), (1, 5), (2, 7)]:
        if max(splits) < len(full_packet):
            packets.append(("attacks", f"tcp_seg_multi_{splits[0]}_{splits[1]}", full_packet,
                           {"cve": "tcp_segmentation", "split_points": list(splits),
                            "note": "send as three TCP segments"}))
            tid += 1

    # Overlapping segments (same data sent twice with different boundaries)
    for overlap_start in [2, 4, 6]:
        for overlap_len in [1, 2, 3]:
            packets.append(("attacks", f"tcp_seg_overlap_{overlap_start}_{overlap_len}", full_packet,
                           {"cve": "tcp_segmentation", "overlap_start": overlap_start,
                            "overlap_length": overlap_len,
                            "note": "overlapping TCP segments"}))
            tid += 1

    # Interleaved malicious: valid header, attack in second request (pipeline)
    for i in range(20):
        # First is valid, second has bad length
        valid_pkt = build_modbus_request(tid, 0x01, FC_READ_HOLDING_REGISTERS,
                                          struct.pack(">HH", 0, 1))
        bad_pdu = bytes([FC_READ_HOLDING_REGISTERS]) + bytes(100)
        bad_pkt = build_raw_packet(tid + 1, 0x0000, 6, 0x01, bad_pdu)
        combined = valid_pkt + bad_pkt
        packets.append(("attacks", f"tcp_seg_pipeline_{i}", combined,
                       {"cve": "tcp_segmentation", "variant": "pipeline",
                        "note": "valid request followed by malformed in same stream"}))
        tid += 2

    return packets[:80]


# ===========================================================================
# Fuzz-generated Packets
# ===========================================================================

def gen_fuzz_packets():
    """Generate randomized malformed packets."""
    packets = []
    tid = 20000

    # Completely random bytes (various lengths)
    for length in [1, 2, 3, 5, 7, 8, 12, 13, 20, 50, 100, 200, 255]:
        for i in range(3):
            data = bytes([random.randint(0, 255) for _ in range(length)])
            packets.append(("fuzz", f"random_{length}b_{i}", data,
                           {"type": "random_bytes", "length": length, "seed_offset": i}))
            tid += 1

    # Valid MBAP header + random PDU
    for i in range(40):
        pdu_len = random.randint(1, 200)
        pdu = bytes([random.randint(0, 255) for _ in range(pdu_len)])
        pkt = build_raw_packet(tid, 0x0000, pdu_len + 1, 0x01, pdu)
        packets.append(("fuzz", f"valid_mbap_random_pdu_{i}", pkt,
                       {"type": "valid_header_random_pdu", "pdu_length": pdu_len}))
        tid += 1

    # Random MBAP header + valid PDU
    for i in range(30):
        trans_id = random.randint(0, 0xFFFF)
        proto_id = random.randint(0, 0xFFFF)
        length = random.randint(0, 0xFFFF)
        unit_id = random.randint(0, 0xFF)
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + struct.pack(">HH", 0, 1)
        pkt = build_raw_packet(trans_id, proto_id, length, unit_id, pdu)
        packets.append(("fuzz", f"random_mbap_valid_pdu_{i}", pkt,
                       {"type": "random_header_valid_pdu",
                        "transaction_id": trans_id, "protocol_id": proto_id,
                        "declared_length": length, "unit_id": unit_id}))
        tid += 1

    # All zeros
    for length in [7, 12, 20, 50, 100]:
        pkt = bytes(length)
        packets.append(("fuzz", f"all_zeros_{length}b", pkt,
                       {"type": "all_zeros", "length": length}))
        tid += 1

    # All 0xFF
    for length in [7, 12, 20, 50, 100]:
        pkt = bytes([0xFF] * length)
        packets.append(("fuzz", f"all_ff_{length}b", pkt,
                       {"type": "all_ones", "length": length}))
        tid += 1

    # Bit-flipped valid packets
    valid_pkt = build_modbus_request(1, 0x01, FC_READ_HOLDING_REGISTERS,
                                      struct.pack(">HH", 0, 1))
    for bit_pos in range(min(len(valid_pkt) * 8, 96)):
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        flipped = bytearray(valid_pkt)
        flipped[byte_idx] ^= (1 << bit_idx)
        packets.append(("fuzz", f"bitflip_pos{bit_pos}", bytes(flipped),
                       {"type": "bit_flip", "bit_position": bit_pos,
                        "byte_index": byte_idx, "bit_index": bit_idx}))
        tid += 1

    # Truncated valid packets
    valid_pkt = build_modbus_request(1, 0x01, FC_READ_HOLDING_REGISTERS,
                                      struct.pack(">HH", 0, 1))
    for trunc_len in range(1, len(valid_pkt)):
        packets.append(("fuzz", f"truncated_{trunc_len}b", valid_pkt[:trunc_len],
                       {"type": "truncated", "original_length": len(valid_pkt),
                        "truncated_length": trunc_len}))
        tid += 1

    # Repeated byte patterns
    for pattern_byte in [0x00, 0x55, 0xAA, 0xFF, 0x41, 0x90]:
        for length in [7, 12, 20, 50]:
            pkt = bytes([pattern_byte] * length)
            packets.append(("fuzz", f"repeated_{pattern_byte:#04x}_{length}b", pkt,
                           {"type": "repeated_byte", "byte": pattern_byte, "length": length}))
            tid += 1

    # Counter patterns (incrementing bytes)
    for start in [0, 64, 128, 192]:
        for length in [12, 20, 50]:
            pkt = bytes([(start + i) & 0xFF for i in range(length)])
            packets.append(("fuzz", f"counter_{start}_{length}b", pkt,
                           {"type": "counter", "start": start, "length": length}))
            tid += 1

    # Valid MBAP but swapped endianness PDU
    for i in range(10):
        addr = random.randint(0, 0xFFFF)
        qty = random.randint(1, 125)
        # Little-endian instead of big-endian
        data = struct.pack("<HH", addr, qty)
        pdu = bytes([FC_READ_HOLDING_REGISTERS]) + data
        pkt = build_raw_packet(tid, 0x0000, len(pdu) + 1, 0x01, pdu)
        packets.append(("fuzz", f"le_endian_{i}", pkt,
                       {"type": "wrong_endianness", "address": addr, "quantity": qty}))
        tid += 1

    return packets[:250]


# ===========================================================================
# Main: Generate corpus and manifest
# ===========================================================================

def main():
    print("Modbus Test Corpus Generator")
    print("=" * 60)

    # Generate all packet categories
    categories = {
        "valid": gen_valid_packets(),
        "malformed": (gen_malformed_mbap_length() +
                      gen_malformed_protocol_id() +
                      gen_malformed_function_codes() +
                      gen_malformed_fc01() +
                      gen_malformed_fc03() +
                      gen_malformed_fc05() +
                      gen_malformed_fc0f() +
                      gen_malformed_fc10() +
                      gen_malformed_cross_field()),
        "attacks": (gen_cve_14462_variants() +
                    gen_cve_0367_variants() +
                    gen_cve_20685_variants() +
                    gen_tcp_segmentation_variants()),
        "fuzz": gen_fuzz_packets(),
    }

    manifest = []
    total = 0

    for category, packets in categories.items():
        cat_dir = CORPUS_DIR / category
        cat_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  {category}: {len(packets)} packets")

        for i, (cat, name, data, meta) in enumerate(packets):
            packet_id = f"{category}_{i:04d}"
            filename = f"{packet_id}.bin"
            filepath = cat_dir / filename

            # Write raw packet bytes
            with open(filepath, "wb") as f:
                f.write(data)

            # Determine expected result
            if category == "valid":
                expected = "pass"
            else:
                expected = "block"

            manifest.append({
                "id": packet_id,
                "filename": filename,
                "category": category,
                "name": name,
                "size": len(data),
                "expected_result": expected,
                "hex_preview": data[:20].hex(),
                **meta
            })
            total += 1

    # Write manifest
    manifest_path = CORPUS_DIR / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump({
            "version": "1.0",
            "total_packets": total,
            "categories": {cat: len(pkts) for cat, pkts in categories.items()},
            "packets": manifest
        }, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"Total packets generated: {total}")
    print(f"Manifest written to: {manifest_path}")
    print(f"\nCategory breakdown:")
    for cat, pkts in categories.items():
        print(f"  {cat:12s}: {len(pkts):4d}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
