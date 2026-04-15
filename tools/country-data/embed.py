#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Generate a C++ source file embedding a binary file as std::array."""
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Embed binary file as C++ std::array")
    parser.add_argument("--input", required=True, type=Path, help="Path to binary input file")
    parser.add_argument("--output", required=True, type=Path, help="Path to C++ output file")
    args = parser.parse_args()

    data = args.input.read_bytes()

    with open(args.output, "w") as out:
        out.write("#include <vanetza/common/byte_view.hpp>\n\n")
        out.write(f"static const std::array<uint8_t, {len(data)}> vanetza_country_data_storage = {{\n")
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            out.write("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n")
        out.write("};\n\n")
        out.write("namespace vanetza {\n")
        out.write("namespace geodesy {\n")
        out.write("namespace country {\n\n")
        out.write("byte_view_range embedded()\n")
        out.write("{\n")
        out.write("    byte_view_iterator begin(vanetza_country_data_storage.data());\n")
        out.write("    byte_view_iterator end(vanetza_country_data_storage.data() + vanetza_country_data_storage.size());\n")
        out.write("    return {begin, end};\n")
        out.write("}\n\n")
        out.write("} // namespace country\n")
        out.write("} // namespace geodesy\n")
        out.write("} // namespace vanetza\n")

    print(f"Embedded {len(data)} bytes into {args.output.name}", file=sys.stderr)


if __name__ == "__main__":
    main()
