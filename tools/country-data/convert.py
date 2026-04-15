#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyshp", "shapely"]
# ///
"""Convert Natural Earth shapefile to Vanetza country data binary format.

Downloads the Natural Earth admin-0 countries shapefile at the requested
resolution, then converts it to a compact binary format.

Output format:
  version   : uint16 (little-endian)
  followed by a sequence of entries, each:
    m49_code  : uint16 (little-endian)
    wkb_size  : uint32 (little-endian)
    wkb_data  : bytes (OGC WKB MultiPolygon)
"""
import argparse
import struct
import sys
import urllib.request
import zipfile
from pathlib import Path

import shapefile
from shapely.geometry import MultiPolygon, Polygon, shape

RESOLUTIONS = ["110m", "50m", "10m"]
FORMAT_VERSION = 1


def download_shapefile(resolution: str, cache_dir: Path) -> Path:
    name = f"ne_{resolution}_admin_0_countries"
    shp_dir = cache_dir / name
    shp_path = shp_dir / f"{name}.shp"

    if shp_path.exists():
        return shp_path

    url = f"https://naciscdn.org/naturalearth/{resolution}/cultural/{name}.zip"
    print(f"Downloading {url} ...", file=sys.stderr)
    data, _ = urllib.request.urlretrieve(url)
    with zipfile.ZipFile(data) as zf:
        shp_dir.mkdir(parents=True, exist_ok=True)
        zf.extractall(shp_dir)

    return shp_path


def convert(shp_path: Path, output: Path):
    sf = shapefile.Reader(str(shp_path))
    fields = [f[0] for f in sf.fields[1:]]  # skip DeletionFlag

    if "ISO_N3_EH" not in fields:
        print("Error: shapefile missing ISO_N3_EH field", file=sys.stderr)
        sys.exit(1)

    iso_n3_eh_idx = fields.index("ISO_N3_EH")
    count = 0
    skipped = 0

    with open(output, "wb") as out:
        out.write(struct.pack("<H", FORMAT_VERSION))

        for sr in sf.shapeRecords():
            iso_n3_eh = sr.record[iso_n3_eh_idx]

            # Skip non-numeric codes (e.g., "-99" for disputed territories)
            try:
                m49 = int(iso_n3_eh)
            except (ValueError, TypeError):
                skipped += 1
                continue

            if m49 < 0 or m49 > 65535:
                skipped += 1
                continue

            geom = shape(sr.shape.__geo_interface__)

            # Normalize to MultiPolygon
            if isinstance(geom, Polygon):
                geom = MultiPolygon([geom])
            elif not isinstance(geom, MultiPolygon):
                skipped += 1
                continue

            wkb = geom.wkb

            out.write(struct.pack("<H", m49))
            out.write(struct.pack("<I", len(wkb)))
            out.write(wkb)
            count += 1

    print(f"Wrote {count} countries, skipped {skipped} entries", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Convert Natural Earth to country data binary")
    parser.add_argument("--output", required=True, type=Path, help="Path to output .bin file")
    parser.add_argument("--resolution", choices=RESOLUTIONS, default="50m",
                        help="Natural Earth resolution (default: 50m)")
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(__file__).parent / "cache",
                        help="Cache directory for downloaded shapefiles")
    args = parser.parse_args()

    shp_path = download_shapefile(args.resolution, args.cache_dir)
    convert(shp_path, args.output)


if __name__ == "__main__":
    main()
