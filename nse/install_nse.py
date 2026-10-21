#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
printerxpl-nse — NSE Script Installer for PrinterXPL-Forge
===========================================================
Copies PrinterXPL-Forge Nmap NSE scripts and the shared printerxpl.lua library
into the active Nmap script directory so they become available system-wide.

Usage:
    printerxpl-nse install           # install scripts
    printerxpl-nse uninstall         # remove scripts
    printerxpl-nse list              # list installed scripts
    printerxpl-nse status            # check installation status
    printerxpl-nse path              # show detected nmap scripts dir
    printerxpl-nse verify            # verify nmap can load the scripts

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ── Package layout ────────────────────────────────────────────────────────────
_THIS_DIR   = Path(__file__).parent.resolve()
_SCRIPTS_DIR = _THIS_DIR / "scripts"
_LIB_DIR    = _THIS_DIR / "lib"

NSE_SCRIPTS = sorted(_SCRIPTS_DIR.glob("*.nse"))
NSE_LIBS    = sorted(_LIB_DIR.glob("*.lua"))
ALL_NSE     = NSE_SCRIPTS + NSE_LIBS

SCRIPT_NAMES  = [f.name for f in NSE_SCRIPTS]
LIB_NAMES     = [f.name for f in NSE_LIBS]

BANNER = r"""
  ____       _       _             __  ______  _     
 |  _ \ _ __(_)_ __ | |_ ___ _ __ \ \/ /  _ \| |    
 | |_) | '__| | '_ \| __/ _ \ '__| >  <| |_) | |    
 |  __/| |  | | | | | ||  __/ |   / /\ \  __/| |___ 
 |_|   |_|  |_|_| |_|\__\___|_|  /_/  \_\_|  |_____|  NSE Installer v5.0.0

  André Henrique (@mrhenrike) | União Geek
  https://github.com/mrhenrike/PrinterXPL-Forge
"""


# ── Nmap detection ────────────────────────────────────────────────────────────

def _find_nmap() -> tuple[str | None, Path | None]:
    """Return (nmap_binary_path, nmap_scripts_dir)."""
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return None, None

    # Ask nmap where its datadir is
    try:
        result = subprocess.run(
            [nmap_bin, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except Exception:
        output = ""

    # Common platform paths
    candidates: list[Path] = []
    system = platform.system()

    if system == "Windows":
        candidates += [
            Path(r"C:\Program Files (x86)\Nmap\scripts"),
            Path(r"C:\Program Files\Nmap\scripts"),
        ]
        nmap_dir = Path(nmap_bin).parent if nmap_bin else None
        if nmap_dir:
            candidates.insert(0, nmap_dir / "scripts")

    elif system == "Darwin":
        candidates += [
            Path("/usr/local/share/nmap/scripts"),
            Path("/opt/homebrew/share/nmap/scripts"),
            Path("/usr/share/nmap/scripts"),
        ]
    else:  # Linux
        candidates += [
            Path("/usr/share/nmap/scripts"),
            Path("/usr/local/share/nmap/scripts"),
            Path("/opt/nmap/share/nmap/scripts"),
        ]

    for c in candidates:
        if c.is_dir():
            return nmap_bin, c

    return nmap_bin, None


def _find_nmap_nselib() -> Path | None:
    """Find the nmap nselib directory for shared libraries."""
    _, scripts_dir = _find_nmap()
    if scripts_dir is None:
        return None
    # nselib is typically sibling of scripts
    nselib = scripts_dir.parent / "nselib"
    if nselib.is_dir():
        return nselib
    return None


# ── Install / uninstall ───────────────────────────────────────────────────────

def cmd_install(args: argparse.Namespace) -> int:
    print(BANNER)
    nmap_bin, scripts_dir = _find_nmap()

    if not nmap_bin:
        print("[ERROR] Nmap not found in PATH. Install nmap first:")
        print("        https://nmap.org/download.html")
        return 1

    print(f"[INFO]  Nmap binary  : {nmap_bin}")

    if scripts_dir is None:
        if args.scripts_dir:
            scripts_dir = Path(args.scripts_dir)
        else:
            print("[ERROR] Nmap scripts directory not found automatically.")
            print("        Use: printerxpl-nse install --scripts-dir /path/to/nmap/scripts")
            return 1

    print(f"[INFO]  Scripts dir  : {scripts_dir}")

    # NSE lib dir
    nselib_dir = _find_nmap_nselib()
    if nselib_dir is None and args.nselib_dir:
        nselib_dir = Path(args.nselib_dir)

    # Copy scripts
    installed = []
    errors    = []

    for src in NSE_SCRIPTS:
        dst = scripts_dir / src.name
        try:
            shutil.copy2(src, dst)
            print(f"[+] Installed  {src.name}  →  {dst}")
            installed.append(src.name)
        except PermissionError:
            print(f"[!] Permission denied: {dst}")
            print(f"    Retry with sudo / Administrator privileges")
            errors.append(src.name)
        except Exception as exc:
            print(f"[!] Failed to copy {src.name}: {exc}")
            errors.append(src.name)

    # Copy shared library (printerxpl.lua)
    for lib in NSE_LIBS:
        # Try nselib first, fall back to scripts dir
        lib_target_dir = nselib_dir or scripts_dir
        dst = lib_target_dir / lib.name
        try:
            shutil.copy2(lib, dst)
            print(f"[+] Installed  {lib.name}  →  {dst}")
            installed.append(lib.name)
        except PermissionError:
            print(f"[!] Permission denied: {dst}")
            errors.append(lib.name)
        except Exception as exc:
            print(f"[!] Failed to copy {lib.name}: {exc}")
            errors.append(lib.name)

    # Update nmap script database
    if installed and not args.no_db_update:
        print("[INFO]  Updating nmap script database (nmap --script-updatedb)…")
        try:
            subprocess.run([nmap_bin, "--script-updatedb"],
                           timeout=30, check=False)
        except Exception as exc:
            print(f"[WARN]  --script-updatedb failed: {exc}")

    print()
    if errors:
        print(f"[WARN]  {len(errors)} file(s) failed — re-run with elevated privileges")
        print(f"[OK]    {len(installed)} file(s) installed successfully")
        return 1
    else:
        print(f"[OK]    {len(installed)} NSE files installed successfully")
        _print_usage_hint()
        return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    print(BANNER)
    _, scripts_dir = _find_nmap()
    if scripts_dir is None and not args.scripts_dir:
        print("[ERROR] Nmap scripts directory not found. Use --scripts-dir")
        return 1
    if args.scripts_dir:
        scripts_dir = Path(args.scripts_dir)

    nselib_dir = _find_nmap_nselib()

    removed = 0
    for name in SCRIPT_NAMES:
        target = scripts_dir / name
        if target.exists():
            try:
                target.unlink()
                print(f"[-] Removed  {target}")
                removed += 1
            except Exception as exc:
                print(f"[!] Could not remove {target}: {exc}")

    for name in LIB_NAMES:
        for search_dir in [nselib_dir, scripts_dir]:
            if search_dir is None:
                continue
            target = search_dir / name
            if target.exists():
                try:
                    target.unlink()
                    print(f"[-] Removed  {target}")
                    removed += 1
                except Exception as exc:
                    print(f"[!] Could not remove {target}: {exc}")

    print(f"\n[OK]  {removed} file(s) removed")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    print(BANNER)
    print(f"PrinterXPL-Forge NSE Bundle  ({len(NSE_SCRIPTS)} scripts + {len(NSE_LIBS)} libs)\n")
    print("Scripts:")
    for s in NSE_SCRIPTS:
        # Extract first @usage line for description
        try:
            lines = s.read_text(encoding="utf-8", errors="replace").splitlines()
            desc  = next((l.strip().lstrip("-").strip() for l in lines if l.strip().startswith("--") and len(l) > 10), "")
        except Exception:
            desc = ""
        print(f"  {s.stem:<35}  {desc[:60]}")
    print()
    print("Shared Libraries:")
    for lib in NSE_LIBS:
        print(f"  {lib.name}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    _, scripts_dir = _find_nmap()
    nmap_bin, _ = _find_nmap()

    print(f"Nmap binary  : {nmap_bin or 'NOT FOUND'}")
    print(f"Scripts dir  : {scripts_dir or 'NOT FOUND'}")
    print()

    if scripts_dir is None:
        print("[NOT INSTALLED]  nmap scripts directory not found")
        return 1

    ok = 0; missing = 0
    for name in SCRIPT_NAMES + LIB_NAMES:
        target = scripts_dir / name
        if target.exists():
            print(f"  [OK]     {name}")
            ok += 1
        else:
            print(f"  [MISSING] {name}")
            missing += 1

    print()
    if missing == 0:
        print(f"[INSTALLED]  All {ok} files present in {scripts_dir}")
        _print_usage_hint()
        return 0
    elif ok == 0:
        print("[NOT INSTALLED]  No files installed yet — run: printerxpl-nse install")
        return 1
    else:
        print(f"[PARTIAL]  {ok} installed, {missing} missing — re-run install")
        return 1


def cmd_path(_: argparse.Namespace) -> int:
    nmap_bin, scripts_dir = _find_nmap()
    print(f"Nmap binary     : {nmap_bin or 'not found'}")
    print(f"Scripts dir     : {scripts_dir or 'not found'}")
    nselib = _find_nmap_nselib()
    print(f"NSElib dir      : {nselib or 'not found'}")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    nmap_bin, scripts_dir = _find_nmap()
    if not nmap_bin:
        print("[ERROR] Nmap not found"); return 1
    if scripts_dir is None:
        print("[ERROR] Scripts dir not found"); return 1

    print("Verifying NSE scripts with nmap --script-help…\n")
    errors = 0
    for name in SCRIPT_NAMES:
        target = scripts_dir / name
        if not target.exists():
            print(f"  [MISSING] {name}")
            errors += 1
            continue
        try:
            result = subprocess.run(
                [nmap_bin, "--script-help", name.replace(".nse", "")],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                print(f"  [OK]     {name}")
            else:
                print(f"  [FAIL]   {name} — {result.stderr.strip()[:80]}")
                errors += 1
        except Exception as exc:
            print(f"  [ERROR]  {name} — {exc}")
            errors += 1

    print()
    if errors:
        print(f"[WARN]  {errors} script(s) failed verification")
        return 1
    print(f"[OK]  All {len(SCRIPT_NAMES)} scripts verified")
    return 0


def _print_usage_hint() -> None:
    print()
    print("=" * 68)
    print("  PrinterXPL-Forge NSE scripts are now available in Nmap!")
    print()
    print("  Quick discovery:")
    print("    nmap -p 9100,631,80 --script printer-discover <target>")
    print()
    print("  Full scan (all scripts):")
    print("    nmap -p 9100,631,80,443,427,515 \\")
    print("         --script 'printer-*' <target>")
    print()
    print("  Targeted checks:")
    print("    nmap -p 9100       --script printer-hp-pjl <target>")
    print("    nmap -p 631        --script printer-cups-rce <target>")
    print("    nmap -p 9100,631,80 --script printer-cve-detect <target>")
    print("    nmap -p 80,443     --script printer-passback <target>")
    print("    nmap -p 445        --script printer-printnightmare <target>")
    print()
    print("  Full exploitation:")
    print("    pip install printerxpl-forge")
    print("    pxf <IP> --scan")
    print("=" * 68)


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="printerxpl-nse",
        description="PrinterXPL-Forge — Nmap NSE script installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")

    # install
    p_install = sub.add_parser("install", help="Install NSE scripts to Nmap")
    p_install.add_argument("--scripts-dir", metavar="PATH",
        help="Override Nmap scripts directory")
    p_install.add_argument("--nselib-dir", metavar="PATH",
        help="Override Nmap nselib directory (for printerxpl.lua)")
    p_install.add_argument("--no-db-update", action="store_true",
        help="Skip nmap --script-updatedb after install")

    # uninstall
    p_uninstall = sub.add_parser("uninstall", help="Remove NSE scripts from Nmap")
    p_uninstall.add_argument("--scripts-dir", metavar="PATH",
        help="Override Nmap scripts directory")

    # list / status / path / verify
    sub.add_parser("list",      help="List all NSE scripts in this bundle")
    sub.add_parser("status",    help="Check installation status")
    sub.add_parser("path",      help="Show detected Nmap directories")
    sub.add_parser("verify",    help="Verify scripts load correctly in Nmap")

    args = parser.parse_args(argv)

    dispatch = {
        "install":   cmd_install,
        "uninstall": cmd_uninstall,
        "list":      cmd_list,
        "status":    cmd_status,
        "path":      cmd_path,
        "verify":    cmd_verify,
    }

    if args.cmd in dispatch:
        return dispatch[args.cmd](args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
