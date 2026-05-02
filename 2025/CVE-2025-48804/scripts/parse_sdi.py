#!/usr/bin/env python3
"""
parse_sdi.py - Parse and display the structure of a Windows SDI file ($SDI0001).

Usage:
    python parse_sdi.py <path_to_boot.sdi>
"""

import struct
import sys
import os
from dataclasses import dataclass
from typing import List, Tuple

SDI_SIGNATURE = b"$SDI0001"
HEADER_SIZE = 512
BLOB_TABLE_OFFSET = 0x200
BLOB_ENTRY_SIZE = 64
BLOB_TABLE_ENTRIES = 64
BLOB_TABLE_SIZE = BLOB_ENTRY_SIZE * BLOB_TABLE_ENTRIES  # 4096
DATA_ALIGNMENT = 0x2000  # 8 KiB

KNOWN_TYPES = {
    b"PART": "PART (raw partition image)",
    b"WIM\x00": "WIM (Windows Imaging Format)",
    b"BOOT": "BOOT (boot code)",
}

@dataclass
class SDIHeader:
    signature: bytes
    raw: bytes

    @classmethod
    def parse(cls, data):
        # type: (bytes) -> SDIHeader
        if len(data) < HEADER_SIZE:
            raise ValueError("Header too short: %d bytes" % len(data))
        return cls(signature=data[0:8], raw=data[:HEADER_SIZE])

    @property
    def is_valid(self):
        return self.signature == SDI_SIGNATURE


@dataclass
class BlobEntry:
    index: int
    type_tag: bytes     # 4 bytes ASCII
    attributes: int
    offset: int         # absolute offset of blob data in file
    size: int           # blob data size
    blob_id: int
    raw: bytes

    @classmethod
    def parse(cls, data, index):
        # type: (bytes, int) -> BlobEntry
        type_tag = data[0:4]
        attributes = struct.unpack_from("<Q", data, 0x08)[0]
        data_offset = struct.unpack_from("<Q", data, 0x10)[0]
        data_size = struct.unpack_from("<Q", data, 0x18)[0]
        blob_id = struct.unpack_from("<Q", data, 0x20)[0]
        return cls(index=index, type_tag=type_tag, attributes=attributes,
                   offset=data_offset, size=data_size, blob_id=blob_id,
                   raw=data[:BLOB_ENTRY_SIZE])

    @property
    def type_name(self):
        return KNOWN_TYPES.get(self.type_tag, "UNKNOWN (%r)" % self.type_tag)

    @property
    def type_short(self):
        tag = self.type_tag.rstrip(b"\x00").decode("ascii", errors="replace")
        return tag if tag else "(empty)"

    @property
    def is_empty(self):
        return self.type_tag == b"\x00\x00\x00\x00" and self.offset == 0 and self.size == 0


def parse_sdi(filepath):
    # type: (str) -> Tuple[SDIHeader, List[BlobEntry]]
    with open(filepath, "rb") as f:
        raw = f.read()
    header = SDIHeader.parse(raw)
    blobs = []
    for i in range(BLOB_TABLE_ENTRIES):
        start = BLOB_TABLE_OFFSET + i * BLOB_ENTRY_SIZE
        if start + BLOB_ENTRY_SIZE > len(raw):
            break
        blobs.append(BlobEntry.parse(raw[start:start + BLOB_ENTRY_SIZE], i))
    return header, blobs


def hex_preview(data, length=64):
    preview = data[:length]
    hx = " ".join("%02x" % b for b in preview)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
    return "%s  |%s|%s" % (hx, asc, "..." if len(data) > length else "")


def format_size(n):
    if n == 0:
        return "0"
    v = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if v < 1024:
            return "%d %s" % (int(v), unit) if v == int(v) else "%.1f %s" % (v, unit)
        v /= 1024
    return "%.2f TiB" % v


def detect_magic(data):
    if len(data) < 4:
        return ""
    if data[:3] == b"\xeb\x52\x90":
        return "NTFS volume (boot sector)"
    if data[:4] == b"MSWI":
        return "WIM image (MSWIM signature)"
    if data[:2] in (b"\xeb\x3c", b"\xeb\x58"):
        return "FAT volume (boot sector)"
    if data[:2] == b"MZ":
        return "PE executable"
    return ""


def display(filepath, header, blobs):
    file_size = os.path.getsize(filepath)

    print("=" * 78)
    print("  SDI FILE ANALYSIS: %s" % filepath)
    print("  File size: %s (%d bytes / 0x%x)" % (format_size(file_size), file_size, file_size))
    print("=" * 78)

    print("\n-- HEADER (512 bytes) --")
    print("  Signature : %r" % header.signature)
    print("  Valid     : %s" % ("Yes" if header.is_valid else "NO - expected %r" % SDI_SIGNATURE))
    print("  Hex (first 64 bytes):")
    print("    %s" % hex_preview(header.raw, 64))

    non_empty = [b for b in blobs if not b.is_empty]
    empty_count = sum(1 for b in blobs if b.is_empty)

    print("\n-- BLOB TABLE at 0x%04x (%d entries, %d non-empty) --" % (
        BLOB_TABLE_OFFSET, len(blobs), len(non_empty)))

    for b in non_empty:
        print("\n  Entry #%d:" % b.index)
        print("    Type tag   : %r  ->  %s" % (b.type_tag, b.type_name))
        print("    Attributes : 0x%016x" % b.attributes)
        print("    Offset     : 0x%08x  (%d)" % (b.offset, b.offset))
        print("    Size       : 0x%08x  (%s)" % (b.size, format_size(b.size)))
        print("    Blob ID    : %d" % b.blob_id)

        end = b.offset + b.size
        if end > file_size:
            print("    WARNING: extends past EOF (end=0x%x, file=0x%x)" % (end, file_size))

        if b.size > 0:
            try:
                with open(filepath, "rb") as f:
                    f.seek(b.offset)
                    preview_data = f.read(min(64, b.size))
                print("    Data hex   : %s" % hex_preview(preview_data, 64))
                magic = detect_magic(preview_data)
                if magic:
                    print("    Detected   : %s" % magic)
            except Exception as e:
                print("    [Read error: %s]" % e)
        else:
            print("    Data       : (empty - size is 0)")

        print("    Entry hex  : %s" % hex_preview(b.raw, 64))

    if empty_count:
        print("\n  (%d empty entries skipped)" % empty_count)

    # Layout map
    print("\n-- LAYOUT MAP --")
    print("  0x%08x - 0x%08x  Header (%d B)" % (0, HEADER_SIZE - 1, HEADER_SIZE))
    bt_end = BLOB_TABLE_OFFSET + BLOB_TABLE_SIZE - 1
    print("  0x%08x - 0x%08x  Blob table (%s)" % (BLOB_TABLE_OFFSET, bt_end, format_size(BLOB_TABLE_SIZE)))

    gap_start = BLOB_TABLE_OFFSET + BLOB_TABLE_SIZE
    data_blobs = sorted([b for b in non_empty if b.size > 0], key=lambda x: x.offset)
    if data_blobs:
        first_data = data_blobs[0].offset
        if gap_start < first_data:
            print("  0x%08x - 0x%08x  Padding (%s)" % (
                gap_start, first_data - 1, format_size(first_data - gap_start)))

    for b in sorted(non_empty, key=lambda x: x.offset):
        if b.size > 0:
            end = b.offset + b.size - 1
            print("  0x%08x - 0x%08x  %s (%s)" % (b.offset, end, b.type_short, format_size(b.size)))
        else:
            print("  0x%08x              %s (empty, size=0)" % (b.offset, b.type_short))

    print("  0x%08x              EOF" % file_size)
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: %s <path_to_boot.sdi>" % sys.argv[0])
        sys.exit(1)
    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print("Error: file not found: %s" % filepath)
        sys.exit(1)
    header, blobs = parse_sdi(filepath)
    display(filepath, header, blobs)


if __name__ == "__main__":
    main()
