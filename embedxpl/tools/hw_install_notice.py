# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Hardware Install Notice Generator for EmbedXPL-Forge.

CLI utility that generates a comprehensive ASCII notice listing all
hardware requirements for modules in a given category, with product
examples, approximate prices, purchase URLs, and driver/tool references.

This helps operators plan hardware procurement before running modules
that depend on physical adapters (BLE dongles, SDR receivers, UART
cables, CAN interfaces, etc.).

Usage:
    python -m embedxpl.tools.hw_install_notice --category wearables
    python -m embedxpl.tools.hw_install_notice --category ot --compact
    python -m embedxpl.tools.hw_install_notice --list-categories
    python -m embedxpl.tools.hw_install_notice --category all --json

Version: 1.0.0
"""

import argparse
import importlib
import json
import os
import sys
import textwrap
from collections import OrderedDict
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_TMP_DIR = _PROJECT_ROOT / ".tmp"


def _import_category_registry():
    """Import the category registry module.

    Returns:
        The categories module reference.

    Raises:
        SystemExit: If the registry module cannot be imported.
    """
    try:
        from embedxpl.registry import categories
        return categories
    except ImportError:
        print("ERROR: Cannot import embedxpl.registry.categories.")
        print("Ensure EmbedXPL-Forge is installed or on sys.path.")
        sys.exit(1)


def _import_hardware_module():
    """Import the core hardware module.

    Returns:
        The hardware module reference.

    Raises:
        SystemExit: If the hardware module cannot be imported.
    """
    try:
        from embedxpl.core import hardware
        return hardware
    except ImportError:
        print("ERROR: Cannot import embedxpl.core.hardware.")
        print("Ensure EmbedXPL-Forge is installed or on sys.path.")
        sys.exit(1)


def _extract_hw_requirements(module_path):
    """Import a module and extract its hardware requirements.

    Args:
        module_path: Dotted Python module path string.

    Returns:
        Tuple of (module_name, hw_list) or None on failure.
        hw_list is a list of hardware identifier strings.
    """
    try:
        mod = importlib.import_module(module_path)
    except Exception:
        return None

    for attr_name in dir(mod):
        obj = getattr(mod, attr_name, None)
        if not isinstance(obj, type):
            continue
        info = getattr(obj, "__info__", None)
        if not isinstance(info, dict):
            continue
        hw_list = info.get("required_hardware", [])
        if hw_list:
            name = info.get("name", module_path.rsplit(".", 1)[-1])
            return (name, list(hw_list))

    return None


def _collect_category_hw(category_name, categories_mod):
    """Collect all hardware requirements for modules in a category.

    Args:
        category_name: Category name string.
        categories_mod: The imported categories module.

    Returns:
        Dict with keys:
            - category: str
            - modules_scanned: int
            - modules_with_hw: int
            - by_hardware: {hw_id: [module_names]}
            - module_details: [{name, module_path, hardware}]
            - unique_hardware: sorted list of hw_id strings
    """
    try:
        module_paths = categories_mod.resolve_category(category_name)
    except ValueError as exc:
        print("ERROR: {e}".format(e=exc))
        sys.exit(1)

    by_hardware = {}
    module_details = []
    scanned = 0

    for mod_path in module_paths:
        scanned += 1
        result = _extract_hw_requirements(mod_path)
        if result is None:
            continue

        name, hw_list = result
        short_path = mod_path.replace("embedxpl.modules.", "")
        module_details.append({
            "name": name,
            "module_path": short_path,
            "hardware": hw_list,
        })

        for hw_id in hw_list:
            if hw_id not in by_hardware:
                by_hardware[hw_id] = []
            by_hardware[hw_id].append(name)

    return {
        "category": category_name,
        "modules_scanned": scanned,
        "modules_with_hw": len(module_details),
        "by_hardware": by_hardware,
        "module_details": module_details,
        "unique_hardware": sorted(by_hardware.keys()),
    }


def _build_notice_header(data):
    """Build the notice header block.

    Args:
        data: Collected hardware data dict.

    Returns:
        Multi-line string with the header section.
    """
    lines = [
        "",
        "=" * 78,
        "  EmbedXPL-Forge - Hardware Install Notice",
        "  Category: {cat}".format(cat=data["category"]),
        "=" * 78,
        "",
        "  Modules scanned            : {n}".format(
            n=data["modules_scanned"],
        ),
        "  Modules requiring hardware : {n}".format(
            n=data["modules_with_hw"],
        ),
        "  Unique hardware types      : {n}".format(
            n=len(data["unique_hardware"]),
        ),
        "",
    ]
    return "\n".join(lines)


def _build_hw_summary_table(data, hw_mod):
    """Build a summary table of hardware requirements.

    Args:
        data: Collected hardware data dict.
        hw_mod: The imported hardware module.

    Returns:
        Multi-line string with formatted ASCII table.
    """
    if not data["unique_hardware"]:
        return (
            "  No hardware-dependent modules found in this category.\n"
            "  All modules can run with standard network connectivity.\n"
        )

    col_id = 22
    col_prod = 32
    col_chip = 24
    col_price = 10
    col_mods = 6

    sep = "+{a}+{b}+{c}+{d}+{e}+".format(
        a="-" * (col_id + 2),
        b="-" * (col_prod + 2),
        c="-" * (col_chip + 2),
        d="-" * (col_price + 2),
        e="-" * (col_mods + 2),
    )
    header = "| {:<{}} | {:<{}} | {:<{}} | {:<{}} | {:<{}} |".format(
        "Hardware ID", col_id,
        "Recommended Product", col_prod,
        "Chipset", col_chip,
        "Price USD", col_price,
        "Mods", col_mods,
    )

    lines = [sep, header, sep]
    total_cost = 0.0

    for hw_id in data["unique_hardware"]:
        summary = hw_mod.get_hardware_summary(hw_id)
        if summary:
            product = summary["product_name"]
            chipset = summary["chipset"]
            price = summary["price_usd"]
            total_cost += price
            price_str = "${:.0f}".format(price)
        else:
            product = "(unknown)"
            chipset = "(unknown)"
            price_str = "$?"

        if len(product) > col_prod:
            product = product[:col_prod - 3] + "..."
        if len(chipset) > col_chip:
            chipset = chipset[:col_chip - 3] + "..."

        mod_count = len(data["by_hardware"].get(hw_id, []))
        lines.append("| {:<{}} | {:<{}} | {:<{}} | {:<{}} | {:<{}} |".format(
            hw_id, col_id,
            product, col_prod,
            chipset, col_chip,
            price_str, col_price,
            str(mod_count), col_mods,
        ))

    lines.append(sep)
    lines.append("")
    lines.append(
        "  Estimated total hardware cost: ${t:.2f} USD".format(t=total_cost)
    )
    lines.append("")
    return "\n".join(lines)


def _build_hw_detail_blocks(data, hw_mod):
    """Build detailed info blocks for each hardware requirement.

    Args:
        data: Collected hardware data dict.
        hw_mod: The imported hardware module.

    Returns:
        Multi-line string with per-hardware detail sections.
    """
    if not data["unique_hardware"]:
        return ""

    blocks = ["-" * 78, "  DETAILED HARDWARE INFORMATION", "-" * 78, ""]

    for hw_id in data["unique_hardware"]:
        summary = hw_mod.get_hardware_summary(hw_id)
        if not summary:
            blocks.append("  [{id}] - No catalog entry".format(id=hw_id))
            blocks.append("")
            continue

        desc = summary.get("description", "No description available.")
        wrapped = textwrap.fill(
            desc, width=72, initial_indent="    ", subsequent_indent="    ",
        )

        blocks.append("  [{id}]".format(id=hw_id))
        blocks.append(wrapped)
        blocks.append(
            "    Product     : {v}".format(v=summary.get("product_name", "N/A"))
        )
        blocks.append(
            "    Chipset     : {v}".format(v=summary.get("chipset", "N/A"))
        )
        blocks.append(
            "    Price       : ${p:.2f} USD".format(
                p=summary.get("price_usd", 0),
            )
        )
        blocks.append(
            "    Purchase    : {v}".format(v=summary.get("buy_url", "N/A"))
        )
        blocks.append(
            "    Drivers     : {v}".format(
                v=", ".join(summary.get("driver_tools", ["-"])),
            )
        )
        blocks.append(
            "    OS Support  : {v}".format(
                v=", ".join(summary.get("os_support", ["-"])),
            )
        )

        mod_names = data["by_hardware"].get(hw_id, [])
        blocks.append(
            "    Used by     : {n} module(s)".format(n=len(mod_names))
        )
        for mod_name in sorted(mod_names):
            blocks.append("      - {m}".format(m=mod_name))
        blocks.append("")

    return "\n".join(blocks)


def _build_module_list(data):
    """Build a per-module hardware breakdown list.

    Args:
        data: Collected hardware data dict.

    Returns:
        Multi-line string with module-level details.
    """
    if not data["module_details"]:
        return ""

    lines = [
        "-" * 78,
        "  MODULE HARDWARE BREAKDOWN",
        "-" * 78,
        "",
    ]

    for entry in sorted(data["module_details"], key=lambda e: e["name"]):
        hw_str = ", ".join(entry["hardware"])
        lines.append("  {name}".format(name=entry["name"]))
        lines.append("    Path     : {p}".format(p=entry["module_path"]))
        lines.append("    Hardware : {h}".format(h=hw_str))
        lines.append("")

    return "\n".join(lines)


def _build_footer():
    """Build the notice footer with warnings and recommendations.

    Returns:
        Multi-line string with footer content.
    """
    lines = [
        "=" * 78,
        "  IMPORTANT NOTES",
        "=" * 78,
        "",
        "  1. Running modules without listed hardware produces connection",
        "     errors, timeouts, or incomplete results.",
        "",
        "  2. Ensure adapters are physically connected and drivers loaded",
        "     before execution.",
        "",
        "  3. Prices are approximate and may vary by region and vendor.",
        "",
        "  4. For modules with no hardware requirements, standard network",
        "     connectivity (Ethernet/Wi-Fi client mode) is sufficient.",
        "",
        "  5. Some adapters require specific kernel modules or firmware.",
        "     Check the driver/tool references above.",
        "",
        "=" * 78,
        "",
    ]
    return "\n".join(lines)


def generate_notice(category_name, compact=False):
    """Generate the full ASCII hardware install notice.

    Args:
        category_name: Category name string.
        compact: If True, omit detailed hardware blocks.

    Returns:
        Complete multi-line notice string.
    """
    categories_mod = _import_category_registry()
    hw_mod = _import_hardware_module()

    data = _collect_category_hw(category_name, categories_mod)

    parts = [
        _build_notice_header(data),
        _build_hw_summary_table(data, hw_mod),
    ]

    if not compact:
        parts.append(_build_hw_detail_blocks(data, hw_mod))
        parts.append(_build_module_list(data))

    parts.append(_build_footer())

    return "\n".join(parts)


def generate_json(category_name):
    """Generate JSON report of hardware requirements for a category.

    Args:
        category_name: Category name string.

    Returns:
        Dict suitable for JSON serialization.
    """
    categories_mod = _import_category_registry()
    hw_mod = _import_hardware_module()

    data = _collect_category_hw(category_name, categories_mod)

    hw_details = {}
    for hw_id in data["unique_hardware"]:
        summary = hw_mod.get_hardware_summary(hw_id)
        if summary:
            hw_details[hw_id] = summary

    return {
        "category": data["category"],
        "modules_scanned": data["modules_scanned"],
        "modules_with_hardware": data["modules_with_hw"],
        "hardware": hw_details,
        "modules": data["module_details"],
    }


def main():
    """Entry point for the hardware install notice CLI."""
    parser = argparse.ArgumentParser(
        prog="embedxpl.tools.hw_install_notice",
        description=(
            "Generate hardware install notice for EmbedXPL-Forge modules "
            "by category."
        ),
    )
    parser.add_argument(
        "--category", "-c",
        type=str,
        default=None,
        metavar="NAME",
        help="Category to inspect (e.g., wearables, routers, ot, all).",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Show summary table only, omit detailed hardware blocks.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output JSON report instead of ASCII notice.",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save output to .tmp/hw_notice_<category>.txt (or .json).",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        dest="list_cats",
        help="List all available categories and exit.",
    )
    args = parser.parse_args()

    if args.list_cats:
        categories_mod = _import_category_registry()
        cats = categories_mod.list_categories()
        print()
        print("Available categories:")
        print()
        for name, desc in cats.items():
            print("  {:<20} {}".format(name, desc))
        print()
        sys.exit(0)

    if not args.category:
        parser.print_help()
        sys.exit(1)

    category = args.category.strip().lower()

    if args.json_output:
        report = generate_json(category)
        output = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
    else:
        output = generate_notice(category, compact=args.compact)

    print(output)

    if args.save:
        os.makedirs(str(_TMP_DIR), exist_ok=True)
        ext = ".json" if args.json_output else ".txt"
        safe_name = category.replace("-", "_")
        filename = "hw_notice_{n}{e}".format(n=safe_name, e=ext)
        filepath = _TMP_DIR / filename
        with open(str(filepath), "w", encoding="utf-8") as fh:
            fh.write(output)
        print("Saved to: {p}".format(p=filepath))


if __name__ == "__main__":
    main()
