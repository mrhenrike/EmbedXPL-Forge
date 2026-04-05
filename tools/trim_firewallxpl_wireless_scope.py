#!/usr/bin/env python3
"""Remove 802.11/BLE generic modules from FirewallXPL-Forge (use WirelessXPL-Forge).

Deletes the same trees as ``trim_routerxpl_wireless_scope`` but under ``firewallxpl/``.

Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
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
    extra = " Wi-Fi/BLE tooling: WirelessXPL-Forge."
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
        default=None,
        help="FirewallXPL-Forge root (default: sibling of RouterXPL-Forge)",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.root is not None:
        root = args.root.resolve()
    else:
        root = Path(__file__).resolve().parents[2] / "FirewallXPL-Forge"
    pkg = root / "firewallxpl"
    if not pkg.is_dir():
        print("Missing {} — pass --root".format(pkg), file=sys.stderr)
        return 2

    _rm(pkg / "modules" / "generic" / "pcap")
    _rm(pkg / "modules" / "generic" / "bluetooth")
    _rm(pkg / "core" / "pcap")
    _rm(pkg / "core" / "bluetooth")
    _patch_scope(pkg)

    print("trim_firewallxpl_wireless_scope: OK -> {}".format(root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
