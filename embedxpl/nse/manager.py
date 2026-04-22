# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — Nmap NSE Script Manager.

Handles installation, removal, listing, and execution of EmbedXPL custom
NSE scripts that extend Nmap with IoT/camera CVE detection and device
fingerprinting capabilities linked to EmbedXPL-Forge exploit modules.

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


# ── Constants ─────────────────────────────────────────────────────────────────

_NSE_PACKAGE_DIR = Path(__file__).parent.parent.parent / "nse"

_SCRIPTS = {
    "rtsp-discover":    "embedxpl-rtsp-discover.nse",
    "camera-identify":  "embedxpl-camera-identify.nse",
    "hikvision-vuln":   "embedxpl-hikvision-vuln.nse",
    "dahua-vuln":       "embedxpl-dahua-vuln.nse",
    "rtsp-creds":       "embedxpl-rtsp-creds.nse",
    "iot-cve-check":    "embedxpl-iot-cve-check.nse",
    "camera-snapshot":  "embedxpl-camera-snapshot.nse",
}

_DESCRIPTIONS = {
    "rtsp-discover":   "RTSP service discovery + banner grab + vendor fingerprint",
    "camera-identify": "IP camera deep fingerprinting (HTTP + RTSP + ONVIF multi-protocol)",
    "hikvision-vuln":  "Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921)",
    "dahua-vuln":      "Dahua CVE checker (CVE-2021-33044, CVE-2020-25078, CVE-2013-6117)",
    "rtsp-creds":      "Quick RTSP default credential tester (Basic auth)",
    "iot-cve-check":   "Multi-vendor IoT CVE fingerprint & active validation (10+ CVEs)",
    "camera-snapshot": "Unauthenticated camera snapshot access detector (30+ endpoints)",
}


def _nmap_script_dir() -> Optional[Path]:
    """Locate Nmap's scripts directory on the current system."""
    candidates = []

    # Common locations per platform
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        candidates = [
            Path("/usr/share/nmap/scripts"),
            Path("/usr/local/share/nmap/scripts"),
            Path("/opt/homebrew/share/nmap/scripts"),
        ]
    elif system == "Windows":
        candidates = [
            Path(r"C:\Program Files (x86)\Nmap\scripts"),
            Path(r"C:\Program Files\Nmap\scripts"),
            Path(os.environ.get("APPDATA", "") + r"\nmap\scripts"),
        ]

    # Also ask nmap itself
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        try:
            result = subprocess.run(
                [nmap_bin, "--version"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "Compiled with" in line or "datadir" in line.lower():
                    # try to extract path
                    pass
        except Exception:
            pass

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


def _nmap_updatedb(nmap_bin: str = "nmap") -> bool:
    """Run ``nmap --script-updatedb`` to register new scripts."""
    try:
        result = subprocess.run(
            [nmap_bin, "--script-updatedb"],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except Exception:
        return False


class NSEManager:
    """Manages EmbedXPL NSE scripts: install, uninstall, list, run.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    def __init__(self, scripts_dir: Optional[Path] = None) -> None:
        """Initialise the NSE manager.

        Args:
            scripts_dir: Override for Nmap scripts directory.
        """
        self._scripts_dir = scripts_dir or _nmap_script_dir()
        self._nmap_bin = shutil.which("nmap") or "nmap"

    # ── Public API ────────────────────────────────────────────────────────────

    def install(self, force: bool = False) -> None:
        """Copy all EmbedXPL NSE scripts to Nmap's scripts directory.

        Args:
            force: Overwrite existing scripts if True.

        Raises:
            RuntimeError: If Nmap's scripts directory cannot be found.
            PermissionError: If write access is denied (try with sudo).
        """
        if not self._scripts_dir:
            raise RuntimeError(
                "Could not find Nmap scripts directory. "
                "Install Nmap first or specify --nse-dir."
            )
        if not _NSE_PACKAGE_DIR.exists():
            raise RuntimeError(
                f"NSE source directory not found: {_NSE_PACKAGE_DIR}\n"
                "Ensure you installed from source: git clone + pip install -e .[nse]"
            )

        installed = []
        skipped = []
        for name, fname in _SCRIPTS.items():
            src = _NSE_PACKAGE_DIR / fname
            dst = self._scripts_dir / fname
            if not src.exists():
                print(f"  [WARN] Script not found: {src}")
                continue
            if dst.exists() and not force:
                skipped.append(name)
                continue
            try:
                shutil.copy2(src, dst)
                installed.append(name)
                print(f"  [OK]   {fname} → {dst}")
            except PermissionError:
                print(f"  [ERR]  Permission denied: {dst}")
                print("         Try: sudo python -m embedxpl.nse install")
                raise

        print(f"\nInstalled: {len(installed)} script(s)")
        if skipped:
            print(f"Skipped (already installed): {len(skipped)} — use --force to overwrite")

        # Update nmap database
        print("\nUpdating nmap script database...")
        if _nmap_updatedb(self._nmap_bin):
            print("  [OK] nmap --script-updatedb complete")
        else:
            print("  [WARN] Could not update nmap db. Run manually:")
            print("         sudo nmap --script-updatedb")

        print("\nInstallation complete. Usage:")
        self._print_usage_hint()

    def uninstall(self) -> None:
        """Remove all EmbedXPL NSE scripts from Nmap's scripts directory."""
        if not self._scripts_dir:
            print("[WARN] Nmap scripts directory not found.")
            return
        removed = 0
        for _, fname in _SCRIPTS.items():
            dst = self._scripts_dir / fname
            if dst.exists():
                try:
                    dst.unlink()
                    print(f"  [OK] Removed: {dst}")
                    removed += 1
                except PermissionError:
                    print(f"  [ERR] Permission denied: {dst}. Try sudo.")
        print(f"\nRemoved {removed} script(s).")
        _nmap_updatedb(self._nmap_bin)

    def list(self) -> None:
        """List all EmbedXPL NSE scripts and their installation status."""
        if not self._scripts_dir:
            print("[WARN] Nmap scripts directory not found.")
        print(f"\n{'NSE Script':<25} {'Status':<15} Description")
        print("─" * 80)
        for name, fname in _SCRIPTS.items():
            if self._scripts_dir:
                status = "INSTALLED" if (self._scripts_dir / fname).exists() else "not installed"
            else:
                status = "unknown"
            desc = _DESCRIPTIONS.get(name, "")
            print(f"  {('embedxpl-' + name):<23} {status:<15} {desc}")
        print()
        self._print_usage_hint()

    def run(self, target: str, scripts: List[str], extra_args: Optional[str] = None,
            ports: str = "80,443,554,5554,8080,8554,37777",
            output_file: Optional[str] = None) -> int:
        """Run Nmap with selected EmbedXPL NSE scripts against a target.

        Args:
            target: IP, CIDR, range, or hostname.
            scripts: List of script short names (e.g. ['rtsp-discover']) or ['all'].
            extra_args: Additional raw nmap arguments string.
            ports: Comma-separated ports to scan.
            output_file: If set, write nmap output to this file.

        Returns:
            Nmap exit code.
        """
        if not shutil.which("nmap"):
            print("[ERROR] nmap not found in PATH. Install nmap first.")
            return 1

        # Resolve script names
        if "all" in scripts:
            script_names = [f"embedxpl-{n}" for n in _SCRIPTS.keys()]
        else:
            script_names = []
            for s in scripts:
                name = s.replace("embedxpl-", "")
                if name in _SCRIPTS:
                    script_names.append(f"embedxpl-{name}")
                else:
                    print(f"[WARN] Unknown script: {s}")

        if not script_names:
            print("[ERROR] No valid scripts specified.")
            return 1

        cmd = [
            self._nmap_bin,
            "-sV",
            "-p", ports,
            "--script", ",".join(script_names),
        ]
        if extra_args:
            cmd.extend(extra_args.split())
        if output_file:
            cmd.extend(["-oN", output_file])
        cmd.append(target)

        print(f"[NSE] Running: {' '.join(cmd)}\n")
        result = subprocess.run(cmd)
        return result.returncode

    def info(self, script_name: str) -> None:
        """Show information about a specific NSE script.

        Args:
            script_name: Short name (e.g. 'rtsp-discover') or full name.
        """
        name = script_name.replace("embedxpl-", "")
        if name not in _SCRIPTS:
            print(f"Unknown script: {script_name}")
            print(f"Available: {', '.join(_SCRIPTS.keys())}")
            return

        fname = _SCRIPTS[name]
        src = _NSE_PACKAGE_DIR / fname
        print(f"\nScript:      embedxpl-{name}")
        print(f"File:        {fname}")
        print(f"Description: {_DESCRIPTIONS[name]}")

        if self._scripts_dir:
            dst = self._scripts_dir / fname
            print(f"Installed:   {'YES' if dst.exists() else 'NO'}")
            if dst.exists():
                print(f"Path:        {dst}")

        if src.exists():
            print(f"\nSource ({src}):")
            with open(src, encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[:30]:
                if line.startswith("--"):
                    print(f"  {line}", end="")
        print()

    # ── CLI ───────────────────────────────────────────────────────────────────

    def cli(self, args: List[str]) -> None:
        """Parse and dispatch CLI commands.

        Args:
            args: sys.argv[1:]
        """
        parser = argparse.ArgumentParser(
            prog="python -m embedxpl.nse",
            description="EmbedXPL-Forge NSE Script Manager",
        )
        sub = parser.add_subparsers(dest="command")

        # install
        p_install = sub.add_parser("install", help="Install NSE scripts to Nmap")
        p_install.add_argument("--force", action="store_true", help="Overwrite existing scripts")
        p_install.add_argument("--nse-dir", help="Override Nmap scripts directory")

        # uninstall
        sub.add_parser("uninstall", help="Remove EmbedXPL NSE scripts from Nmap")

        # list
        sub.add_parser("list", help="List EmbedXPL NSE scripts and status")

        # run
        p_run = sub.add_parser("run", help="Run NSE scripts against a target")
        p_run.add_argument("--target", "-t", required=True, help="Target IP/CIDR/hostname")
        p_run.add_argument("--scripts", "-s", default="all",
                           help="Scripts to run: all, or comma-separated names")
        p_run.add_argument("--ports", "-p", default="80,443,554,5554,8080,8554,37777")
        p_run.add_argument("--output", "-o", help="Output file path")
        p_run.add_argument("--args", help="Extra nmap arguments")

        # info
        p_info = sub.add_parser("info", help="Show info for a specific script")
        p_info.add_argument("script", help="Script name (e.g. rtsp-discover)")

        parsed = parser.parse_args(args)

        if parsed.command == "install":
            if hasattr(parsed, "nse_dir") and parsed.nse_dir:
                self._scripts_dir = Path(parsed.nse_dir)
            self.install(force=parsed.force)

        elif parsed.command == "uninstall":
            self.uninstall()

        elif parsed.command == "list":
            self.list()

        elif parsed.command == "run":
            script_list = [s.strip() for s in parsed.scripts.split(",")]
            sys.exit(self.run(
                target=parsed.target,
                scripts=script_list,
                extra_args=getattr(parsed, "args", None),
                ports=parsed.ports,
                output_file=getattr(parsed, "output", None),
            ))

        elif parsed.command == "info":
            self.info(parsed.script)

        else:
            parser.print_help()

    def _print_usage_hint(self) -> None:
        """Print common usage examples."""
        print("Quick start:")
        print("  nmap -p 554,5554,8554 --script embedxpl-rtsp-discover 192.168.1.0/24")
        print("  nmap -p 80,443 --script 'embedxpl-*' 192.168.1.100")
        print("  nmap -p 80,443,554 --script embedxpl-iot-cve-check 192.168.1.0/24")
        print("  python -m embedxpl.nse run --target 192.168.1.0/24 --scripts all")
        print()
        print("Full exploitation (after NSE detection):")
        print("  pip install embedxpl && embedxpl")
        print("  embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack")
