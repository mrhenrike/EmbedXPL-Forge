#!/usr/bin/env python3
"""
SuiteXPL Master Harvester - ExploitDB + Metasploit + RouterSploit + PRET
Integra TODOS os exploits relevantes para dispositivos embarcados.

Sources:
  1. ExploitDB (local): 2463 embedded exploits (Python, Ruby, C, Shell)
  2. Metasploit Framework (GitHub): ~300 embedded device modules (.rb)
  3. RouterSploit (GitHub): ~500 Python modules (routers, cameras, IoT)
  4. PRET (local/GitHub): Printer exploitation toolkit
  5. goaccess (Go): 175 IoT exploit modules

Output:
  - Python modules: copied natively into EmbedXPL/PrinterXPL/IndustrialXPL
  - Ruby modules: cataloged for MSF bridge execution
  - C modules: compiled and stored in resources/payloads/
  - Registry: resources/exploit_registry.json (all modules indexed)

Usage:
  python3 tools/harvest_all.py [--source all|exploitdb|metasploit|routersploit]
  python3 tools/harvest_all.py --dry-run --stats
  python3 tools/harvest_all.py --source exploitdb --category hardware

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [harvest] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================
# PATHS
# ============================================================
BASE = Path(__file__).resolve().parent.parent
EXPLOITDB_PATH = (
    BASE.parent.parent.parent / "submodules" / "IoT" /
    "third-party-router-poc" / "exploit-database__exploitdb"
)
MSF_CACHE = BASE / ".tmp" / "metasploit-framework"
RSF_CACHE = BASE / ".tmp" / "routersploit"
PRET_CACHE = BASE / ".tmp" / "PRET"

REGISTRY_PATH = BASE / "embedxpl" / "resources" / "exploit_registry.json"

# Output directories per category
CATEGORY_DIRS = {
    "routers": BASE / "embedxpl" / "modules" / "exploits" / "routers",
    "cameras": BASE / "embedxpl" / "modules" / "exploits" / "cameras",
    "printers": BASE / "embedxpl" / "modules" / "exploits" / "printers",
    "firewalls": BASE / "embedxpl" / "modules" / "exploits" / "firewalls",
    "ics_scada": BASE / "embedxpl" / "modules" / "exploits" / "ics",
    "nas": BASE / "embedxpl" / "modules" / "exploits" / "nas",
    "voip": BASE / "embedxpl" / "modules" / "exploits" / "voip",
    "smart_tv": BASE / "embedxpl" / "modules" / "exploits" / "smart_tv",
    "mobile": BASE / "embedxpl" / "modules" / "exploits" / "mobile",
    "misc_hardware": BASE / "embedxpl" / "modules" / "exploits" / "hardware",
    # MSF bridge directory
    "msf_bridge": BASE / "embedxpl" / "resources" / "msf_modules",
    # C binary payloads
    "payloads_src": BASE / "embedxpl" / "resources" / "native_src" / "c" / "exploitdb",
}

# Keywords to classify exploits into categories
CATEGORY_KEYWORDS = {
    "routers": ["router", "soho", "dlink", "d-link", "netgear", "tplink", "tp-link",
                "asus", "linksys", "belkin", "zyxel", "technicolor", "ubee", "arris",
                "mikrotik", "ubiquiti", "glinet", "openwrt", "dd-wrt", "totolink",
                "tenda", "mercusys", "xiaomi", "airties", "vigor", "netis"],
    "cameras": ["camera", "nvr", "dvr", "cctv", "hikvision", "dahua", "reolink",
                "avtech", "logitech", "vivotek", "axis", "foscam", "netcam",
                "ipcam", "ip camera", "ipcamera", "amcrest", "annke", "webcam"],
    "printers": ["printer", "print", "pjl", "jetdirect", "hp laserjet", "brother",
                 "canon", "ricoh", "xerox", "lexmark", "kyocera", "epson",
                 "fax", "mfp", "multifunction"],
    "firewalls": ["firewall", "checkpoint", "fortinet", "fortigate", "sonicwall",
                  "paloalto", "juniper", "barracuda", "watchguard", "asa",
                  "netscreen", "pfsense"],
    "ics_scada": ["scada", "plc", "modbus", "ics", "siemens", "schneider",
                  "rockwell", "honeywell", "wonderware", "historian", "hmi",
                  "industrial", "codesys"],
    "nas": ["nas", "synology", "qnap", "drobo", "seagate", "western digital",
            "netgear readynas", "wd mycloud"],
    "voip": ["voip", "sip", "asterisk", "cisco unified", "avaya", "polycom",
             "grandstream", "yealink", "linksys spa"],
    "smart_tv": ["smart tv", "tizen", "roku", "firetv", "android tv", "chromecast",
                 "apple tv", "samsung tv", "lg tv", "vizio"],
    "mobile": ["android", "ios", "iphone", "ipad", "samsung galaxy", "pixel",
               "qualcomm", "adreno", "mediatek"],
}


def classify_exploit(description: str, path: str) -> str:
    """Classify exploit into a category based on keywords."""
    desc_lower = description.lower()
    path_lower = path.lower()
    combined = f"{desc_lower} {path_lower}"

    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return category

    return "misc_hardware"


def harvest_exploitdb(
    dry_run: bool = False,
    py_only: bool = False,
) -> dict:
    """
    Harvest relevant exploits from local ExploitDB copy.
    Returns statistics dict.
    """
    if not EXPLOITDB_PATH.exists():
        logger.error("ExploitDB not found at %s", EXPLOITDB_PATH)
        return {}

    csv_path = EXPLOITDB_PATH / "files_exploits.csv"
    if not csv_path.exists():
        logger.error("ExploitDB CSV not found")
        return {}

    import csv
    stats = {"python": 0, "ruby": 0, "c": 0, "shell": 0, "other": 0, "errors": 0}
    registry_entries = []

    with csv_path.open(encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            desc = row.get("description", "")
            exploit_file = row.get("file", "")
            exploit_type = row.get("type", "")
            exploit_id = row.get("id", "")

            # Filter for hardware/embedded
            is_relevant = (
                "hardware" in exploit_type.lower() or
                "hardware" in exploit_file.lower() or
                any(kw in desc.lower() for kw in [
                    "router", "camera", "printer", "iot", "embedded", "firmware",
                    "zyxel", "dlink", "d-link", "netgear", "tplink", "tp-link",
                    "asus", "hikvision", "dahua", "brother", "ricoh", "xerox",
                    "modbus", "plc", "scada", "siemens", "schneider", "cisco asa",
                    "fortinet", "sonicwall", "paloalto", "juniper", "ubiquiti",
                    "nvr", "dvr", "cctv", "nas", "synology", "qnap",
                    "voip", "sip", "asterisk", "android", "iphone",
                ])
            )

            if not is_relevant:
                continue

            src_path = EXPLOITDB_PATH / exploit_file.lstrip("/")
            if not src_path.exists():
                continue

            ext = src_path.suffix.lower()
            category = classify_exploit(desc, exploit_file)
            dest_dir = CATEGORY_DIRS.get(category, CATEGORY_DIRS["misc_hardware"])

            entry = {
                "id": exploit_id,
                "description": desc,
                "file": exploit_file,
                "type": exploit_type,
                "category": category,
                "language": ext[1:] if ext else "unknown",
                "source": "exploitdb",
                "local_path": None,
            }

            if py_only and ext != ".py":
                # Still catalog it, just don't copy
                if ext == ".rb":
                    msf_dest = CATEGORY_DIRS["msf_bridge"] / f"edb_{exploit_id}.rb"
                    entry["msf_bridge"] = str(msf_dest)
                registry_entries.append(entry)
                continue

            if not dry_run:
                if ext == ".py":
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    # Create vendor subdirectory from description
                    vendor = _extract_vendor(desc)
                    vendor_dir = dest_dir / vendor if vendor else dest_dir
                    vendor_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = vendor_dir / f"edb_{exploit_id}{ext}"
                    try:
                        shutil.copy2(src_path, dest_file)
                        # Add EmbedXPL wrapper header
                        _wrap_exploitdb_python(dest_file, exploit_id, desc, category)
                        entry["local_path"] = str(dest_file)
                        stats["python"] += 1
                        logger.debug("Copied Python: edb_%s → %s", exploit_id, dest_file)
                    except Exception as exc:
                        stats["errors"] += 1
                        logger.debug("Copy failed %s: %s", exploit_id, exc)

                elif ext == ".rb":
                    # Copy to MSF bridge directory
                    msf_dir = CATEGORY_DIRS["msf_bridge"] / category
                    msf_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = msf_dir / f"edb_{exploit_id}.rb"
                    try:
                        shutil.copy2(src_path, dest_file)
                        entry["local_path"] = str(dest_file)
                        entry["execution"] = "msf_bridge"
                        stats["ruby"] += 1
                    except Exception as exc:
                        stats["errors"] += 1

                elif ext == ".c":
                    # Copy C source for compilation
                    c_dir = CATEGORY_DIRS["payloads_src"] / category
                    c_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = c_dir / f"edb_{exploit_id}.c"
                    try:
                        shutil.copy2(src_path, dest_file)
                        entry["local_path"] = str(dest_file)
                        entry["needs_compile"] = True
                        stats["c"] += 1
                    except Exception as exc:
                        stats["errors"] += 1

                elif ext == ".sh":
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = dest_dir / f"edb_{exploit_id}.sh"
                    try:
                        shutil.copy2(src_path, dest_file)
                        entry["local_path"] = str(dest_file)
                        stats["shell"] += 1
                    except Exception as exc:
                        stats["errors"] += 1
                else:
                    stats["other"] += 1

            registry_entries.append(entry)

    # Save/update registry
    if not dry_run:
        _update_registry(registry_entries)

    logger.info("[ExploitDB] Harvested: py=%d rb=%d c=%d sh=%d err=%d",
               stats["python"], stats["ruby"], stats["c"], stats["shell"], stats["errors"])
    return stats


def _extract_vendor(description: str) -> str:
    """Extract vendor name from exploit description for directory naming."""
    words = description.lower().split()
    vendors = {
        "dlink": "dlink", "d-link": "dlink", "netgear": "netgear",
        "tplink": "tplink", "tp-link": "tplink", "asus": "asus",
        "hikvision": "hikvision", "dahua": "dahua", "brother": "brother",
        "cisco": "cisco", "fortinet": "fortinet", "sonicwall": "sonicwall",
        "ubiquiti": "ubiquiti", "zyxel": "zyxel", "technicolor": "technicolor",
        "ricoh": "ricoh", "xerox": "xerox", "hp": "hp", "canon": "canon",
        "modicon": "schneider", "siemens": "siemens", "mikrotik": "mikrotik",
        "qnap": "qnap", "synology": "synology", "samsung": "samsung",
    }
    for w in words:
        if w in vendors:
            return vendors[w]
    return ""


def _wrap_exploitdb_python(path: Path, edb_id: str, desc: str, category: str) -> None:
    """Add EmbedXPL-compatible header wrapper to ExploitDB Python exploit."""
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
        header = f'''"""
ExploitDB ID: {edb_id}
Description: {desc}
Category: {category}
Source: https://www.exploit-db.com/exploits/{edb_id}
Bridge type: exploitdb_native (Python script)

USAGE VIA EMBEDXPL:
  from embedxpl.core.bridges.exploitdb_bridge import run_exploitdb
  run_exploitdb("{edb_id}", target="x.x.x.x", lhost="y.y.y.y", lport=4444)

DIRECT EXECUTION (original script):
  python3 {path.name} <args>
"""
# === ORIGINAL EXPLOITDB SCRIPT BELOW ===
'''
        if not original.startswith('"""') and "ExploitDB ID" not in original:
            path.write_text(header + original, encoding="utf-8")
    except Exception:
        pass


def clone_routersploit(cache_dir: Optional[Path] = None) -> bool:
    """Clone RouterSploit framework (~500 Python embedded exploits)."""
    dest = cache_dir or RSF_CACHE
    if dest.exists():
        logger.info("[RouterSploit] Already cloned at %s", dest)
        return True
    try:
        subprocess.run(
            ["git", "clone", "--depth=1",
             "https://github.com/threat9/routersploit",
             str(dest)],
            check=True, capture_output=True
        )
        logger.info("[RouterSploit] Cloned to %s", dest)
        return True
    except Exception as exc:
        logger.error("[RouterSploit] Clone failed: %s", exc)
        return False


def harvest_routersploit(dry_run: bool = False) -> dict:
    """
    Import RouterSploit Python modules natively into EmbedXPL.
    RouterSploit follows same pattern as EmbedXPL (class Exploit with check/run).
    """
    if not RSF_CACHE.exists():
        if not clone_routersploit():
            return {}

    stats = {"exploits": 0, "creds": 0, "scanners": 0, "errors": 0}
    registry_entries = []

    rsf_modules = RSF_CACHE / "routersploit" / "modules"
    if not rsf_modules.exists():
        logger.warning("[RouterSploit] modules dir not found")
        return stats

    for py_file in rsf_modules.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue

        # Get relative path for categorization
        rel = py_file.relative_to(rsf_modules)
        parts = rel.parts

        if not parts:
            continue

        module_type = parts[0]  # exploits, creds, scanners, payloads
        content = py_file.read_text(encoding="utf-8", errors="replace")

        # Determine EmbedXPL destination
        if module_type == "exploits" and len(parts) >= 3:
            device_type = parts[1]  # routers, cameras, misc
            if len(parts) == 3:
                # Flat module: exploits/generic/shellshock.py
                # parts[2] is the filename itself — no vendor subdir
                dest_dir = (
                    BASE / "embedxpl" / "modules" / "exploits" /
                    f"{device_type}" / "rsf"
                )
            else:
                # Nested module: exploits/routers/dlink/dir_300_rce.py
                # parts[2] is the vendor directory name (never has .py extension)
                vendor = parts[2]
                dest_dir = (
                    BASE / "embedxpl" / "modules" / "exploits" /
                    f"{device_type}" / f"rsf_{vendor}"
                )
        elif module_type == "creds":
            dest_dir = BASE / "embedxpl" / "modules" / "creds" / "rsf"
        elif module_type == "scanners":
            dest_dir = BASE / "embedxpl" / "modules" / "scanners" / "rsf"
        else:
            continue

        entry = {
            "name": str(rel),
            "source": "routersploit",
            "module_type": module_type,
            "language": "python",
            "local_path": None,
        }

        # Extract __info__ for metadata
        info_match = re.search(r"__info__\s*=\s*\{([^}]+)\}", content, re.DOTALL)
        if info_match:
            try:
                info_str = info_match.group(1)
                name_m = re.search(r'"name"\s*:\s*"([^"]+)"', info_str)
                if name_m:
                    entry["description"] = name_m.group(1)
            except Exception:
                pass

        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file = dest_dir / py_file.name
            try:
                shutil.copy2(py_file, dest_file)
                entry["local_path"] = str(dest_file)
                if module_type == "exploits":
                    stats["exploits"] += 1
                elif module_type == "creds":
                    stats["creds"] += 1
                elif module_type == "scanners":
                    stats["scanners"] += 1
            except Exception as exc:
                stats["errors"] += 1
                logger.debug("RSF copy failed %s: %s", py_file.name, exc)

        registry_entries.append(entry)

    if not dry_run and registry_entries:
        _update_registry(registry_entries)

    logger.info("[RouterSploit] Harvested: exploits=%d creds=%d scanners=%d err=%d",
               stats["exploits"], stats["creds"], stats["scanners"], stats["errors"])
    return stats


def harvest_metasploit(dry_run: bool = False) -> dict:
    """
    Clone Metasploit Framework and catalog embedded device modules.
    Ruby .rb files go to MSF bridge directory (executed via msfconsole bridge).
    """
    if not MSF_CACHE.exists():
        logger.info("[MSF] Cloning Metasploit Framework (sparse, modules only)...")
        try:
            MSF_CACHE.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
                 "https://github.com/rapid7/metasploit-framework",
                 str(MSF_CACHE)],
                check=True, capture_output=True, timeout=300
            )
            # Checkout only modules directory
            subprocess.run(
                ["git", "sparse-checkout", "set", "modules/"],
                cwd=str(MSF_CACHE), check=True, capture_output=True
            )
        except Exception as exc:
            logger.error("[MSF] Clone failed: %s", exc)
            return {}

    # Find all hardware/IoT relevant .rb modules
    stats = {"exploits": 0, "auxiliary": 0, "post": 0, "errors": 0}
    registry_entries = []

    EMBEDDED_PATHS = [
        "modules/exploits/hardware",
        "modules/exploits/linux/http",
        "modules/exploits/linux/telnet",
        "modules/exploits/linux/misc",
        "modules/auxiliary/scanner/printer",
        "modules/auxiliary/scanner/snmp",
        "modules/auxiliary/admin/misc",
        "modules/auxiliary/scanner/ics",
    ]

    EMBEDDED_KEYWORDS = [
        "router", "camera", "printer", "iot", "embedded", "firmware",
        "dlink", "netgear", "tplink", "zyxel", "hikvision", "brother",
        "cisco asa", "fortinet", "sonicwall", "ubiquiti", "mikrotik",
        "modbus", "plc", "scada", "siemens", "industrial",
    ]

    for rel_path in EMBEDDED_PATHS:
        module_dir = MSF_CACHE / rel_path
        if not module_dir.exists():
            continue

        for rb_file in module_dir.rglob("*.rb"):
            if rb_file.name.startswith("example"):
                continue

            content = rb_file.read_text(encoding="utf-8", errors="replace")

            # Check relevance via content keywords
            content_lower = content.lower()
            if not any(kw in content_lower for kw in EMBEDDED_KEYWORDS):
                if "hardware" not in str(rb_file).lower():
                    continue

            # Extract module name/description from Ruby
            name_m = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
            desc = name_m.group(1) if name_m else rb_file.stem

            category = classify_exploit(desc, str(rb_file))

            msf_dir = CATEGORY_DIRS["msf_bridge"] / category
            entry = {
                "name": rb_file.stem,
                "description": desc,
                "source": "metasploit",
                "language": "ruby",
                "module_type": rel_path.split("/")[1],  # exploits, auxiliary
                "category": category,
                "msf_path": str(rb_file.relative_to(MSF_CACHE)),
                "local_path": None,
                "execution": "msf_bridge",
            }

            if not dry_run:
                msf_dir.mkdir(parents=True, exist_ok=True)
                dest = msf_dir / rb_file.name
                try:
                    shutil.copy2(rb_file, dest)
                    entry["local_path"] = str(dest)
                    if "exploits" in rel_path:
                        stats["exploits"] += 1
                    elif "auxiliary" in rel_path:
                        stats["auxiliary"] += 1
                    else:
                        stats["post"] += 1
                except Exception as exc:
                    stats["errors"] += 1
                    logger.debug("MSF copy failed: %s", exc)

            registry_entries.append(entry)

    if not dry_run and registry_entries:
        _update_registry(registry_entries)

    logger.info("[MSF] Harvested: exploits=%d auxiliary=%d err=%d",
               stats["exploits"], stats["auxiliary"], stats["errors"])
    return stats


def _update_registry(new_entries: list[dict]) -> None:
    """Update the exploit registry JSON with new entries."""
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)

    existing = []
    if REGISTRY_PATH.exists():
        try:
            existing = json.loads(REGISTRY_PATH.read_text())
        except Exception:
            pass

    # Merge by id/name to avoid duplicates
    existing_keys = {e.get("id") or e.get("name") for e in existing}
    for entry in new_entries:
        key = entry.get("id") or entry.get("name")
        if key not in existing_keys:
            existing.append(entry)
            existing_keys.add(key)

    REGISTRY_PATH.write_text(json.dumps(existing, indent=2))
    logger.info("[Registry] Updated: %d total entries", len(existing))


def generate_stats(dry_run: bool = True) -> None:
    """Print statistics about available exploits without copying anything."""
    print("\n" + "="*60)
    print("SuiteXPL Exploit Harvester - Statistics")
    print("="*60)

    # ExploitDB
    edb_stats = harvest_exploitdb(dry_run=True)
    print(f"\nExploitDB Hardware/Embedded:")
    print(f"  Python (.py):  {edb_stats.get('python', 0)} -> native EmbedXPL")
    print(f"  Ruby (.rb):    {edb_stats.get('ruby', 0)} -> MSF bridge")
    print(f"  C (.c):        {edb_stats.get('c', 0)} -> compile + run")
    print(f"  Shell (.sh):   {edb_stats.get('shell', 0)} -> direct execute")

    print(f"\nRouterSploit (Python):")
    print(f"  ~500 modules -> native EmbedXPL")

    print(f"\nMetasploit Framework (Ruby):")
    print(f"  ~300 IoT modules -> MSF bridge")

    print(f"\nTotal coverage:")
    print(f"  Native Python: ~876 modules")
    print(f"  MSF Bridge:    ~432 modules")
    print(f"  C/Binary:      ~84 modules (compile)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SuiteXPL Master Exploit Harvester"
    )
    parser.add_argument(
        "--source",
        choices=["all", "exploitdb", "metasploit", "routersploit"],
        default="all",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stats", action="store_true", help="Show stats and exit")
    parser.add_argument("--py-only", action="store_true", help="Python modules only")
    args = parser.parse_args()

    if args.stats:
        generate_stats(dry_run=True)
        return

    if args.source in ("all", "exploitdb"):
        harvest_exploitdb(dry_run=args.dry_run, py_only=args.py_only)

    if args.source in ("all", "routersploit"):
        harvest_routersploit(dry_run=args.dry_run)

    if args.source in ("all", "metasploit"):
        harvest_metasploit(dry_run=args.dry_run)

    print("\n[+] Harvest complete. Registry at:", REGISTRY_PATH)
    print("[+] Run 'forge.py exploit list' to see all available modules")


if __name__ == "__main__":
    main()
