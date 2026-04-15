#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["matplotlib", "shapely"]
# ///
"""Plot country polygons from a Vanetza country data binary file."""
import argparse
import colorsys
import struct
import sys

import matplotlib.pyplot as plt
from shapely import wkb

EXPECTED_FORMAT_VERSION = 1


def main():
    parser = argparse.ArgumentParser(description="Plot country polygons from .bin file")
    parser.add_argument("input", help="Path to country_data.bin")
    args = parser.parse_args()

    fig, ax = plt.subplots(figsize=(16, 8))

    with open(args.input, "rb") as f:
        data = f.read()

    if len(data) < 2:
        print("Error: file too short to contain version header", file=sys.stderr)
        sys.exit(1)

    version, = struct.unpack_from("<H", data, 0)
    if version != EXPECTED_FORMAT_VERSION:
        print(f"Error: unsupported country data format version {version}", file=sys.stderr)
        sys.exit(1)

    offset = 2
    while offset < len(data):
        m49, = struct.unpack_from("<H", data, offset)
        offset += 2
        wkb_size, = struct.unpack_from("<I", data, offset)
        offset += 4
        geom = wkb.loads(data[offset:offset + wkb_size])
        offset += wkb_size

        h = (m49 * 0.618) % 1.0
        s = 0.5 + (hash(m49) % 50) / 100.0
        l = 0.4 + (hash(m49 * 7) % 30) / 100.0
        color = colorsys.hls_to_rgb(h, l, s)

        for polygon in geom.geoms:
            x, y = polygon.exterior.xy
            ax.fill(x, y, alpha=0.4, edgecolor="black", linewidth=0.3, facecolor=color)
            if polygon.area > 1.0:
                centroid = polygon.centroid
                ax.text(centroid.x, centroid.y, str(m49),
                        fontsize=5, ha="center", va="center")

    ax.set_aspect("equal")
    ax.set_xlabel("Longitude")
    ax.set_ylabel("Latitude")
    ax.set_title("Country Polygons")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
