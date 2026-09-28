# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Hardware Requirements Audit Tool for EmbedXPL-Forge.

CLI utility that scans all exploit and scanner modules via importlib,
extracts __info__["required_hardware"] from each, groups results by
HWReq canonical identifier, and outputs an ASCII summary table plus
a JSON report to .tmp/hw_audit.json.

Usage:
    python -m embedxpl.tools.hw_requirements_audit
    python -m embedxpl.tools.hw_requirements_audit --json-only
    python -m embedxpl.tools.hw_requirements_audit --filter ble_adapter

Version: 1.0.0
"""

import argparse
import importlib
import json
import os
import pkgutil
import sys
import time
from collections import defaultdict
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MODULES_BASE = _PROJECT_ROOT / "embedxpl" / "modules"
_TMP_DIR = _PROJECT_ROOT / ".tmp"
_AUDIT_OUTPUT = _TMP_DIR / "hw_audit.json"

_SCAN_PACKAGES = [
    "embedxpl.modules.exploits",
    "embedxpl.modules.scanners",
]


def _discover_module_paths():
    """Walk module packages and yield importable dotted paths.

    Yields:
        Strings like 'embedxpl.modules.exploits.routers.dlink.dlink_rce'.
    """
    for base_pkg in _SCAN_PACKAGES:
        try:
            base = importlib.import_module(base_pkg)
        except ImportError:
            continue
        if not hasattr(base, "__path__"):
            continue
        for importer, modname, ispkg in pkgutil.walk_packages(
            base.__path__, prefix=base_pkg + "."
        ):
            if ispkg:
                continue
            if modname.endswith("__init__"):
                continue
            yield modname


def _extract_info(module_path):
    """Import a module and extract its __info__ dict.

    Args:
        module_path: Dotted Python module path string.

    Returns:
        Tuple of (module_path, info_dict) or None on failure.
    """
    try:
        mod = importlib.import_module(module_path)
    except Exception:
        return None

    for attr_name in dir(mod):
        obj = getattr(mod, attr_name, None)
        if not isinstance(obj, type):
            continue
        for key in dir(obj):
            if key.endswith("__info__") and not key.startswith("__"):
                info = getattr(obj, key, None)
                if isinstance(info, dict):
                    return (module_path, info)
            if key == "__info__":
                info = getattr(obj, key, None)
                if isinstance(info, dict):
                    return (module_path, info)
    return None


def _build_audit_data(filter_hw=None):
    """Scan all modules and build the audit data structure.

    Args:
        filter_hw: Optional string to filter by specific hardware ID.

    Returns:
        Dict with keys:
            - modules_scanned: int
            - modules_with_hardware: int
            - by_hardware: {hw_id: [module_paths]}
            - by_module: {module_path: {name, required_hardware}}
            - unrecognized: {hw_id: [module_paths]}
            - timestamp: ISO 8601 string
    """
    from embedxpl.core.hardware import HWReq

    known_ids = {m.value for m in HWReq}
    by_hardware = defaultdict(list)
    by_module = {}
    unrecognized = defaultdict(list)
    scanned = 0
    with_hw = 0

    for mod_path in _discover_module_paths():
        scanned += 1
        result = _extract_info(mod_path)
        if result is None:
            continue

        path, info = result
        hw_list = info.get("required_hardware", [])
        if not hw_list:
            continue

        with_hw += 1
        module_name = info.get("name", path.rsplit(".", 1)[-1])
        by_module[path] = {
            "name": module_name,
            "required_hardware": list(hw_list),
        }

        for hw_id in hw_list:
            if hw_id in known_ids:
                by_hardware[hw_id].append(path)
            else:
                unrecognized[hw_id].append(path)

    if filter_hw:
        by_hardware = {
            k: v for k, v in by_hardware.items() if k == filter_hw
        }
        by_module = {
            k: v for k, v in by_module.items()
            if filter_hw in v.get("required_hardware", [])
        }

    return {
        "modules_scanned": scanned,
        "modules_with_hardware": with_hw,
        "by_hardware": dict(by_hardware),
        "by_module": by_module,
        "unrecognized": dict(unrecognized),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


def _print_ascii_table(audit):
    """Print a summary ASCII table to stdout.

    Args:
        audit: Audit data dict from _build_audit_data().
    """
    print()
    print("=" * 78)
    print("  EmbedXPL-Forge - Hardware Requirements Audit")
    print("=" * 78)
    print()
    print("  Modules scanned     : {n}".format(n=audit["modules_scanned"]))
    print("  Modules with HW req : {n}".format(n=audit["modules_with_hardware"]))
    print("  Distinct HW types   : {n}".format(n=len(audit["by_hardware"])))
    print()

    if not audit["by_hardware"]:
        print("  No hardware-dependent modules found.")
        print()
        return

    sep = "+{a}+{b}+{c}+".format(
        a="-" * 26, b="-" * 8, c="-" * 40,
    )
    header = "| {:<24} | {:<6} | {:<38} |".format(
        "Hardware ID", "Count", "Example Module",
    )
    print(sep)
    print(header)
    print(sep)

    for hw_id in sorted(audit["by_hardware"].keys()):
        modules = audit["by_hardware"][hw_id]
        example = modules[0].rsplit(".", 1)[-1] if modules else ""
        if len(example) > 38:
            example = example[:35] + "..."
        print("| {:<24} | {:<6} | {:<38} |".format(
            hw_id, len(modules), example,
        ))
    print(sep)
    print()

    if audit["unrecognized"]:
        print("  Unrecognized hardware identifiers:")
        for hw_id, paths in sorted(audit["unrecognized"].items()):
            print("    {id} ({n} module(s))".format(id=hw_id, n=len(paths)))
        print()

    print("  Detail by hardware type:")
    print()
    for hw_id in sorted(audit["by_hardware"].keys()):
        modules = audit["by_hardware"][hw_id]
        print("  [{id}] - {n} module(s):".format(id=hw_id, n=len(modules)))
        for mod_path in sorted(modules):
            short = mod_path.replace("embedxpl.modules.", "")
            print("    - {p}".format(p=short))
        print()


def _save_json(audit):
    """Write audit data to JSON file in .tmp/ directory.

    Args:
        audit: Audit data dict from _build_audit_data().
    """
    os.makedirs(str(_TMP_DIR), exist_ok=True)
    with open(str(_AUDIT_OUTPUT), "w", encoding="utf-8") as fh:
        json.dump(audit, fh, indent=2, ensure_ascii=False, sort_keys=True)
    print("  JSON report saved to: {p}".format(p=_AUDIT_OUTPUT))


def main():
    """Entry point for the hardware requirements audit CLI."""
    parser = argparse.ArgumentParser(
        description="Audit hardware requirements across EmbedXPL-Forge modules.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output JSON report only, suppress ASCII table.",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        metavar="HW_ID",
        help="Filter results to a specific hardware identifier (e.g., ble_adapter).",
    )
    args = parser.parse_args()

    audit = _build_audit_data(filter_hw=args.filter)

    if not args.json_only:
        _print_ascii_table(audit)

    _save_json(audit)
    print()


if __name__ == "__main__":
    main()
