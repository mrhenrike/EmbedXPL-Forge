# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Documentation generator for EmbedXPL-Forge modules.

Scans all Python modules under ``embedxpl/modules/exploits/`` and
``embedxpl/modules/scanners/``, reads each module's ``__info__`` dict,
and generates Markdown documentation files with a consistent template.

Supports per-module docs, category INDEX files, hardware-requirements
aggregation, and a statistics mode that prints an ASCII summary table.

Usage:
    python -m embedxpl.tools.docgen --lang en-US --output docs/en-US/
    python -m embedxpl.tools.docgen --lang all
    python -m embedxpl.tools.docgen --stats

Version: 1.0.0
"""

import argparse
import importlib
import os
import pkgutil
import sys
import textwrap
import traceback
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple


_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
)

_MODULE_ROOTS = (
    "embedxpl.modules.exploits",
    "embedxpl.modules.scanners",
)

_DEFAULT_OUTPUT = os.path.join(_PROJECT_ROOT, "docs", "en-US")
_SUPPORTED_LANGS = ("en-US", "pt-BR")

_TMP_DIR = os.path.join(_PROJECT_ROOT, ".tmp")


# ---------------------------------------------------------------------------
# Module discovery
# ---------------------------------------------------------------------------

def _ensure_project_on_path() -> None:
    """Ensure the project root is on sys.path for import resolution."""
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)


def _walk_packages(root_pkg: str) -> List[Tuple[str, str]]:
    """Recursively discover all sub-modules under *root_pkg*.

    Args:
        root_pkg: Dotted package name (e.g. ``embedxpl.modules.exploits``).

    Returns:
        List of (dotted_module_name, category_label) tuples.
    """
    _ensure_project_on_path()
    results: List[Tuple[str, str]] = []

    try:
        pkg = importlib.import_module(root_pkg)
    except ImportError:
        return results

    pkg_path = getattr(pkg, "__path__", None)
    if pkg_path is None:
        return results

    for importer, modname, ispkg in pkgutil.walk_packages(
        pkg_path, prefix=root_pkg + "."
    ):
        if ispkg:
            continue
        if modname.endswith(".__init__"):
            continue
        parts = modname.split(".")
        # category is the segment right after exploits/ or scanners/
        root_parts = root_pkg.split(".")
        category = parts[len(root_parts)] if len(parts) > len(root_parts) else "misc"
        results.append((modname, category))

    return results


def _import_module_info(dotted_name: str) -> Optional[Dict[str, Any]]:
    """Import a module and extract its ``__info__`` dict.

    The metaclass ``ExploitOptionsAggregator`` renames ``__info__`` to
    ``_ClassName__info__`` at class creation time. This function looks
    for both the direct attribute and the mangled form on the ``Exploit``
    class defined in the module.

    Args:
        dotted_name: Fully qualified Python module name.

    Returns:
        The ``__info__`` dict, or None if unavailable.
    """
    try:
        mod = importlib.import_module(dotted_name)
    except Exception:
        return None

    exploit_cls = getattr(mod, "Exploit", None)
    if exploit_cls is None:
        return None

    # Direct attribute (set before metaclass processes it)
    info = getattr(exploit_cls, "__info__", None)
    if info and isinstance(info, dict):
        return dict(info)

    # Mangled by ExploitOptionsAggregator: _Exploit__info__
    for attr in dir(exploit_cls):
        if attr.endswith("__info__") and not attr.startswith("__"):
            candidate = getattr(exploit_cls, attr, None)
            if isinstance(candidate, dict):
                return dict(candidate)

    return None


def _collect_options(dotted_name: str) -> List[Dict[str, str]]:
    """Extract Option descriptors from a module's Exploit class.

    Args:
        dotted_name: Fully qualified Python module name.

    Returns:
        List of dicts with keys: name, type, default, description.
    """
    try:
        mod = importlib.import_module(dotted_name)
    except Exception:
        return []

    exploit_cls = getattr(mod, "Exploit", None)
    if exploit_cls is None:
        return []

    from embedxpl.core.exploit.option import Option

    params: List[Dict[str, str]] = []
    for name in sorted(dir(exploit_cls)):
        if name.startswith("_"):
            continue
        obj = None
        try:
            obj = exploit_cls.__dict__.get(name)
            if obj is None:
                for base in exploit_cls.__mro__:
                    obj = base.__dict__.get(name)
                    if obj is not None:
                        break
        except Exception:
            continue
        if obj is not None and isinstance(obj, Option):
            params.append({
                "name": name,
                "type": type(obj).__name__,
                "default": str(getattr(obj, "display_value", "")),
                "description": str(getattr(obj, "description", "")),
            })

    return params


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

_MODULE_TEMPLATE = textwrap.dedent("""\
    # {name}

    > {description}

    | Field | Value |
    |-------|-------|
    | **Module** | `{module_path}` |
    | **Authors** | {authors} |
    | **CVE** | {cve} |
    | **CVSS** | {cvss} |
    | **Severity** | {severity} |
    | **Status** | {status} |
    | **MITRE** | {mitre} |
    | **APT Groups** | {apt_groups} |

    ## Affected Devices

    {devices}

    ## Prerequisites

    {prerequisites}

    ## Parameters

    | Name | Type | Default | Description |
    |------|------|---------|-------------|
    {params_table}

    ## Syntax

    ```
    use {module_use_path}
    show options
    set target <IP>
    run
    ```

    ## How it Works

    {how_it_works}

    ## Limitations

    {limitations}

    ## Remediation

    {remediation}

    ## Required Hardware

    {hardware_section}

    ## References

    {references}
""")


def _join_or_na(value: Any, sep: str = ", ") -> str:
    """Join iterable values or return 'N/A'."""
    if not value:
        return "N/A"
    if isinstance(value, (list, tuple)):
        return sep.join(str(v) for v in value)
    return str(value)


def _bullet_list(items: Any) -> str:
    """Format items as a Markdown bullet list."""
    if not items:
        return "- N/A"
    if isinstance(items, str):
        return "- {}".format(items)
    return "\n".join("- {}".format(item) for item in items)


def _build_module_doc(
    dotted_name: str,
    info: Dict[str, Any],
    options: List[Dict[str, str]],
) -> str:
    """Build a Markdown document for a single module.

    Args:
        dotted_name: Fully qualified module path.
        info: The module's __info__ dict.
        options: Extracted Option descriptors.

    Returns:
        Complete Markdown string.
    """
    params_rows = []
    for opt in options:
        params_rows.append("| `{name}` | {type} | `{default}` | {description} |".format(
            **opt
        ))
    params_table = "\n".join(params_rows) if params_rows else "| - | - | - | No configurable parameters |"

    use_path = dotted_name.replace("embedxpl.modules.", "").replace(".", "/")

    hw_list = info.get("required_hardware", [])
    if hw_list:
        hw_lines = ["This module requires physical hardware:\n"]
        for hw_id in hw_list:
            hw_lines.append("- `{}`".format(hw_id))
        hardware_section = "\n".join(hw_lines)
    else:
        hardware_section = "No special hardware required. Network access only."

    refs = info.get("references", [])
    if refs:
        ref_lines = []
        for r in refs:
            ref_lines.append("- <{}>".format(r))
        references = "\n".join(ref_lines)
    else:
        references = "- No external references listed."

    description = info.get("description", "No description available.")
    how_it_works = (
        "Refer to the module source for implementation details. "
        "The module follows the standard Exploit base class lifecycle: "
        "`check()` for detection, `run()` for exploitation."
    )
    limitations = (
        "- Target must be reachable on the specified port.\n"
        "- Results depend on firmware version and patch level."
    )
    remediation = (
        "- Apply vendor patches and firmware updates.\n"
        "- Restrict network access to management interfaces.\n"
        "- Monitor for indicators of compromise listed in references."
    )
    prerequisites = _bullet_list(info.get("prerequisites", [
        "Network connectivity to the target device",
    ]))

    return _MODULE_TEMPLATE.format(
        name=info.get("name", "Unknown Module"),
        description=description,
        module_path=dotted_name,
        authors=_join_or_na(info.get("authors")),
        cve=info.get("cve", "N/A"),
        cvss=info.get("cvss", "N/A"),
        severity=info.get("severity", "N/A"),
        status=info.get("status", "unverified"),
        mitre=_join_or_na(info.get("mitre")),
        apt_groups=_join_or_na(info.get("apt_groups")),
        devices=_bullet_list(info.get("devices")),
        prerequisites=prerequisites,
        params_table=params_table,
        module_use_path=use_path,
        how_it_works=how_it_works,
        limitations=limitations,
        remediation=remediation,
        hardware_section=hardware_section,
        references=references,
    )


def _build_index(
    category: str,
    entries: List[Tuple[str, Dict[str, Any]]],
) -> str:
    """Build an INDEX.md for a module category.

    Args:
        category: Category label (e.g. "cameras", "routers").
        entries: List of (dotted_name, info_dict) tuples.

    Returns:
        Markdown string with a summary table.
    """
    lines = [
        "# {} Modules Index".format(category.replace("_", " ").title()),
        "",
        "| Module Name | CVE | CVSS | Status | Attack Class |",
        "|-------------|-----|------|--------|--------------|",
    ]
    for dotted_name, info in sorted(entries, key=lambda e: e[0]):
        mod_file = dotted_name.split(".")[-1]
        name = info.get("name", mod_file)
        cve = info.get("cve", "N/A")
        cvss = info.get("cvss", "N/A")
        status = info.get("status", "unverified")
        severity = info.get("severity", "N/A")
        link = "[{}](./{}.md)".format(name, mod_file)
        lines.append("| {} | {} | {} | {} | {} |".format(
            link, cve, cvss, status, severity,
        ))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hardware requirements doc
# ---------------------------------------------------------------------------

def _build_hardware_doc() -> str:
    """Generate hardware-requirements.md from the hardware module data.

    Returns:
        Markdown string documenting all HWReq entries.
    """
    try:
        from embedxpl.core.hardware import (
            HWReq,
            HARDWARE_DESCRIPTIONS,
            HARDWARE_EXAMPLES,
        )
    except ImportError:
        return "# Hardware Requirements\n\nCould not import hardware module.\n"

    lines = [
        "# Hardware Requirements",
        "",
        "This document lists all physical hardware adapters that EmbedXPL-Forge",
        "modules may require. Each entry includes a recommended product,",
        "chipset information, approximate pricing, purchase links, required",
        "drivers/tools, and OS compatibility.",
        "",
        "Modules declare their requirements via the `required_hardware` key in",
        "the `__info__` dict. The framework's hardware gate (`embedxpl.core.hardware`)",
        "warns the operator before execution when adapters are needed.",
        "",
        "---",
        "",
    ]

    for member in sorted(HWReq, key=lambda m: m.value):
        desc = HARDWARE_DESCRIPTIONS.get(member, "No description.")
        ex = HARDWARE_EXAMPLES.get(member, {})

        lines.append("## {} (`{}`)".format(
            member.name.replace("_", " ").title(),
            member.value,
        ))
        lines.append("")
        lines.append(desc)
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append("| **Product** | {} |".format(ex.get("product_name", "N/A")))
        lines.append("| **Chipset** | {} |".format(ex.get("chipset", "N/A")))
        lines.append("| **Price (USD)** | ${:.2f} |".format(ex.get("price_usd", 0)))
        lines.append("| **Purchase** | <{}> |".format(ex.get("buy_url", "N/A")))
        lines.append("| **Drivers/Tools** | {} |".format(
            ", ".join(ex.get("driver_tools", ["-"])),
        ))
        lines.append("| **OS Support** | {} |".format(
            ", ".join(ex.get("os_support", ["-"])),
        ))
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _compute_stats(
    all_modules: List[Tuple[str, str, Optional[Dict[str, Any]]]],
) -> Dict[str, Any]:
    """Compute aggregate statistics from discovered modules.

    Args:
        all_modules: List of (dotted_name, category, info_or_None).

    Returns:
        Dict with keys: total, confirmed, untested_prod, protocols,
        os_targets, categories, errors.
    """
    total = len(all_modules)
    confirmed = 0
    untested_prod = 0
    protocols = set()
    os_targets = set()
    categories = set()
    errors = 0

    for dotted_name, category, info in all_modules:
        categories.add(category)
        if info is None:
            errors += 1
            continue
        status = str(info.get("status", "")).lower()
        if status == "confirmed":
            confirmed += 1
        elif status in ("untested-prod", "untested_prod"):
            untested_prod += 1
        for dev in info.get("devices", []):
            dev_lower = str(dev).lower()
            for os_name in ("linux", "windows", "macos", "freebsd", "rtos", "vxworks"):
                if os_name in dev_lower:
                    os_targets.add(os_name)
        refs = info.get("references", [])
        for ref in refs:
            ref_lower = str(ref).lower()
            for proto in ("http", "https", "ftp", "ssh", "telnet", "snmp",
                          "rtsp", "modbus", "s7", "mqtt", "coap", "upnp"):
                if proto in ref_lower:
                    protocols.add(proto)

    return {
        "total": total,
        "confirmed": confirmed,
        "untested_prod": untested_prod,
        "protocols": sorted(protocols),
        "os_targets": sorted(os_targets),
        "categories": sorted(categories),
        "errors": errors,
    }


def _print_stats_table(stats: Dict[str, Any]) -> None:
    """Print an ASCII table with module statistics to stdout.

    Args:
        stats: Dict returned by ``_compute_stats``.
    """
    total = stats["total"]
    confirmed = stats["confirmed"]
    untested = stats["untested_prod"]
    errors = stats["errors"]

    conf_pct = (confirmed / total * 100) if total > 0 else 0
    unt_pct = (untested / total * 100) if total > 0 else 0

    sep = "+" + "-" * 34 + "+" + "-" * 34 + "+"
    fmt = "| {:<32} | {:<32} |"

    print()
    print(sep)
    print(fmt.format("Metric", "Value"))
    print(sep)
    print(fmt.format("Total Modules", str(total)))
    print(fmt.format("CONFIRMED", "{} ({:.1f}%)".format(confirmed, conf_pct)))
    print(fmt.format("UNTESTED-PROD", "{} ({:.1f}%)".format(untested, unt_pct)))
    print(fmt.format("Import Errors", str(errors)))
    print(fmt.format("Categories", str(len(stats["categories"]))))
    print(fmt.format("Protocol Coverage", ", ".join(stats["protocols"]) or "N/A"))
    print(fmt.format("OS Targets", ", ".join(stats["os_targets"]) or "N/A"))
    print(sep)
    print()


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _safe_write(filepath: str, content: str) -> bool:
    """Write content to a file, creating parent directories as needed.

    Args:
        filepath: Absolute or relative path for the output file.
        content: String content to write.

    Returns:
        True on success, False on failure.
    """
    try:
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        return True
    except OSError as exc:
        print("[ERROR] Failed to write {}: {}".format(filepath, exc),
              file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Main generation pipeline
# ---------------------------------------------------------------------------

def generate_docs(output_dir: str, lang: str = "en-US") -> Dict[str, Any]:
    """Run the full documentation generation pipeline.

    Args:
        output_dir: Root directory for generated docs.
        lang: Language tag (currently only affects output path).

    Returns:
        Dict with keys: generated, errors, stats.
    """
    _ensure_project_on_path()
    os.makedirs(_TMP_DIR, exist_ok=True)

    modules_dir = os.path.join(output_dir, "modules")
    os.makedirs(modules_dir, exist_ok=True)

    all_modules: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []
    category_map: Dict[str, List[Tuple[str, Dict[str, Any]]]] = OrderedDict()
    generated = 0
    error_modules: List[str] = []

    for root_pkg in _MODULE_ROOTS:
        discovered = _walk_packages(root_pkg)
        for dotted_name, category in discovered:
            info = _import_module_info(dotted_name)
            all_modules.append((dotted_name, category, info))

            if info is None:
                error_modules.append(dotted_name)
                print("[WARN] Could not import: {}".format(dotted_name),
                      file=sys.stderr)
                continue

            options = _collect_options(dotted_name)
            doc = _build_module_doc(dotted_name, info, options)

            parts = dotted_name.split(".")
            root_parts = root_pkg.split(".")
            relative_parts = parts[len(root_parts):]
            filename = relative_parts[-1] + ".md"
            subdir = os.path.join(modules_dir, *relative_parts[:-1])
            filepath = os.path.join(subdir, filename)

            if _safe_write(filepath, doc):
                generated += 1

            if category not in category_map:
                category_map[category] = []
            category_map[category].append((dotted_name, info))

    for category, entries in category_map.items():
        index_content = _build_index(category, entries)
        index_path = os.path.join(modules_dir, category, "INDEX.md")
        _safe_write(index_path, index_content)

    hw_doc = _build_hardware_doc()
    hw_path = os.path.join(output_dir, "hardware-requirements.md")
    _safe_write(hw_path, hw_doc)

    stats = _compute_stats(all_modules)

    return {
        "generated": generated,
        "errors": error_modules,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the docgen CLI."""
    parser = argparse.ArgumentParser(
        prog="embedxpl.tools.docgen",
        description="Generate Markdown documentation from EmbedXPL-Forge modules.",
    )
    parser.add_argument(
        "--lang",
        default="en-US",
        choices=list(_SUPPORTED_LANGS) + ["all"],
        help="Language for generated docs (default: en-US). Use 'all' for every supported language.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory (default: docs/<lang>/). Ignored when --lang=all.",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        default=False,
        help="Print module statistics table and exit.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for the documentation generator.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code: 0 on success, 1 on errors.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    _ensure_project_on_path()

    if args.stats:
        all_modules: List[Tuple[str, str, Optional[Dict[str, Any]]]] = []
        for root_pkg in _MODULE_ROOTS:
            for dotted_name, category in _walk_packages(root_pkg):
                info = _import_module_info(dotted_name)
                all_modules.append((dotted_name, category, info))
        stats = _compute_stats(all_modules)
        _print_stats_table(stats)
        return 0

    langs = list(_SUPPORTED_LANGS) if args.lang == "all" else [args.lang]
    exit_code = 0

    for lang in langs:
        if args.output and len(langs) == 1:
            output_dir = args.output
        else:
            output_dir = os.path.join(_PROJECT_ROOT, "docs", lang)

        print("[*] Generating docs for '{}' -> {}".format(lang, output_dir))
        result = generate_docs(output_dir, lang=lang)
        print("[+] Generated: {} module docs".format(result["generated"]))

        if result["errors"]:
            print("[!] {} modules failed to import:".format(len(result["errors"])))
            for err_mod in result["errors"]:
                print("    - {}".format(err_mod))
            exit_code = 1

        _print_stats_table(result["stats"])

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
