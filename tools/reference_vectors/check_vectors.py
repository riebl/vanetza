"""Cross-decode the synthetic corpus using an explicitly installed pycrate module."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

MESSAGES = {
    "mapem": ("MAPEM_PDU_Descriptions", "MAPEM", 5),
    "spatem": ("SPATEM_PDU_Descriptions", "SPATEM", 4),
    "srem": ("SREM_PDU_Descriptions", "SREM", 9),
    "ssem": ("SSEM_PDU_Descriptions", "SSEM", 10),
}


def _sequence(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    children = list(element)
    names = [child.tag for child in children]
    if sorted(names) != sorted(value):
        errors.append(f"{path}: XER components {names}, decoded {sorted(value)}")
        return
    for child in children:
        compare(child, value[child.tag], path + "." + child.tag, errors)


def _sequence_of(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    children = list(element)
    if len(children) != len(value):
        errors.append(f"{path}: {len(children)} XER elements, {len(value)} decoded")
        return
    for index, (child, item) in enumerate(zip(children, value, strict=True)):
        compare(child, item, f"{path}[{index}]", errors)


def _tuple(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    if len(value) != 2:
        errors.append(f"{path}: unsupported decoded tuple")
    elif isinstance(value[0], str):
        children = list(element)
        if len(children) != 1 or children[0].tag != value[0]:
            errors.append(f"{path}: wrong XER alternative for {value[0]}")
        else:
            compare(children[0], value[1], path + "." + value[0], errors)
    else:
        bits = "".join((element.text or "").split())
        decoded = format(value[0], f"0{value[1]}b") if value[1] else ""
        if bits != decoded:
            errors.append(f"{path}: XER bits {bits}, decoded {decoded}")


def _boolean(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    children = list(element)
    if len(children) != 1 or children[0].tag != ("true" if value else "false"):
        errors.append(f"{path}: XER boolean differs from {value}")


def _integer(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    if (element.text or "").strip() != str(value):
        errors.append(f"{path}: XER integer differs from {value}")


def _string(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    children = list(element)
    if children:
        if len(children) != 1 or children[0].tag != value:
            errors.append(f"{path}: XER enumerated value differs from {value}")
    elif (element.text or "") != value:
        errors.append(f"{path}: XER text differs from {value!r}")


def _octets(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    if "".join((element.text or "").split()).lower() != value.hex():
        errors.append(f"{path}: XER octets differ from {value.hex()}")


def compare(element: ElementTree.Element, value: Any, path: str, errors: list[str]) -> None:
    """Compare each ASN.1 value with its basic XER representation."""
    handlers = (
        (dict, _sequence),
        (list, _sequence_of),
        (tuple, _tuple),
        (bool, _boolean),
        (int, _integer),
        (str, _string),
        (bytes, _octets),
    )
    for kind, handler in handlers:
        if isinstance(value, kind):
            handler(element, value, path, errors)
            return
    errors.append(f"{path}: unsupported decoded value {value!r}")


def check_entry(directory: Path, entry: dict[str, Any], modules: Any) -> list[str]:
    module_name, type_name, message_id = MESSAGES[entry["message"]]
    asn_type = getattr(getattr(modules, module_name), type_name)
    uper = (directory / (entry["name"] + ".uper")).read_bytes()
    xer = ElementTree.parse(directory / (entry["name"] + ".xer")).getroot()
    asn_type.from_uper(uper)
    value = asn_type.get_val()
    errors: list[str] = []
    if asn_type.to_uper() != uper:
        errors.append("UPER decode/re-encode changed the bytes")
    if len(uper) != entry["bytes"]:
        errors.append(f"size {len(uper)} differs from manifest {entry['bytes']}")
    if value["header"]["messageID"] != message_id:
        errors.append("unexpected messageID")
    if xer.tag != type_name:
        errors.append(f"XER root {xer.tag}, expected {type_name}")
    compare(xer, value, type_name, errors)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--module", default="pycrate_asn1dir.ITS")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads((args.directory / "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, list) or not manifest:
            raise ValueError("manifest must contain at least one vector")
        modules = importlib.import_module(args.module)
        print(f"pycrate {importlib.metadata.version('pycrate')}, {args.module}")
    except (OSError, ValueError, ImportError) as error:
        print(f"vector setup failed: {error}", file=sys.stderr)
        return 2

    failures = 0
    for entry in manifest:
        try:
            errors = check_entry(args.directory, entry, modules)
        except Exception as error:
            errors = [f"{type(error).__name__}: {error}"]
        failures += bool(errors)
        print(f"{entry.get('name', '<unnamed>')}: {'FAILED' if errors else 'ok'}")
        for detail in errors[:20]:
            print(f"  {detail}")
    print(f"{len(manifest) - failures} of {len(manifest)} vectors match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
