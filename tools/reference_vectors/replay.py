"""Replay committed XER seeds through the current Vanetza reference-vector codec."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def replay(directory: Path, codec: Path, output: Path) -> int:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, list) or not manifest:
        raise ValueError("manifest must contain at least one vector")
    output.mkdir(parents=True, exist_ok=True)
    for entry in manifest:
        name = entry["name"]
        seed = directory / (name + ".xer")
        uper = output / (name + ".uper")
        xer = output / (name + ".xer")
        subprocess.run(
            [str(codec), entry["message"], "xer-to-uper", str(seed), str(uper)], check=True
        )
        subprocess.run(
            [str(codec), entry["message"], "uper-to-xer", str(uper), str(xer)], check=True
        )
        if uper.read_bytes() != (directory / (name + ".uper")).read_bytes():
            raise ValueError(f"{name}: reproduced UPER differs from committed bytes")
        if xer.read_bytes() != seed.read_bytes():
            raise ValueError(f"{name}: reproduced XER differs from committed seed")
        print(f"{name}: identical")
    return len(manifest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--codec", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        codec = args.codec.resolve(strict=True)
        if args.output is None:
            with tempfile.TemporaryDirectory(prefix="vanetza-vectors-") as temporary:
                count = replay(args.directory, codec, Path(temporary))
        else:
            if args.output.resolve() == args.directory.resolve():
                raise ValueError("output must differ from the committed corpus directory")
            count = replay(args.directory, codec, args.output)
        print(f"{count} vectors reproduced")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"vector replay failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
