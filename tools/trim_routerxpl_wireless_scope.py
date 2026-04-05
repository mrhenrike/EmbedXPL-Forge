#!/usr/bin/env python3
"""Remove 802.11/BLE offline modules from RouterXPL-Forge (moved to WirelessXPL-Forge).

Deletes:
  - routerxpl/modules/generic/pcap/
  - routerxpl/modules/generic/bluetooth/
  - routerxpl/core/pcap/
  - routerxpl/core/bluetooth/

Updates ``module_target_scope.json`` note.Wireless line and drops prefix rules that only
matched PCAP paths (optional cleanup).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Iterable


def _rm(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    elif path.is_file():
        path.unlink(missing_ok=True)


def _patch_scope(pkg: Path) -> None:
    path = pkg / "resources" / "catalogs" / "module_target_scope.json"
    if not path.is_file():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    note = data.get("note") or ""
    extra = (
        " Wireless / BLE PCAP and live BT modules live in WirelessXPL-Forge "
        "(https://github.com/mrhenrike/WirelessXPL-Forge)."
    )
    if "WirelessXPL-Forge" not in note:
        data["note"] = (note.rstrip() + extra).strip()
    rules = data.get("prefix_rules") or []
    data["prefix_rules"] = [
        r
        for r in rules
        if not str(r.get("prefix", "")).startswith(("generic/pcap/", "generic/bluetooth/"))
    ]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="RouterXPL-Forge root",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    root: Path = args.root.resolve()
    pkg = root / "routerxpl"
    if not pkg.is_dir():
        print("Missing {}".format(pkg), file=sys.stderr)
        return 2

    _rm(pkg / "modules" / "generic" / "pcap")
    _rm(pkg / "modules" / "generic" / "bluetooth")
    _rm(pkg / "core" / "pcap")
    _rm(pkg / "core" / "bluetooth")
    _patch_scope(pkg)

    print("trim_routerxpl_wireless_scope: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
