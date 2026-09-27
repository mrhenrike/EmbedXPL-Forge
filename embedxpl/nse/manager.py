# Author: Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
"""EmbedXPL-Forge -- Nmap NSE Script Manager.

Handles installation, removal, listing, and execution of EmbedXPL custom
NSE scripts that extend Nmap with IoT/camera/firewall CVE detection and device
fingerprinting linked to EmbedXPL-Forge and FirewallXPL-Forge exploit modules.

Install workflow
----------------
1. Validate Nmap is installed on the system (multi-method detection).
2. Locate Nmap's scripts directory (nmap binary, common paths, OS package mgr).
3. If Nmap NOT found:
   - Inform the user clearly.
   - Print the local NSE file paths so the user can copy them manually.
   - Exit without error (non-blocking).
4. If Nmap found:
   - Copy each .nse file to the scripts directory.
   - Run ``nmap --script-updatedb`` to register new scripts.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 2.0.0
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# NSE script catalog (short-name -> filename)
# ---------------------------------------------------------------------------

_NSE_PACKAGE_DIR = Path(__file__).parent.parent.parent / "nse"

_SCRIPTS: Dict[str, str] = {
    # Cameras / NVR / RTSP
    "rtsp-discover":    "embedxpl-rtsp-discover.nse",
    "camera-identify":  "embedxpl-camera-identify.nse",
    "camera-snapshot":  "embedxpl-camera-snapshot.nse",
    "hikvision-vuln":   "embedxpl-hikvision-vuln.nse",
    "dahua-vuln":       "embedxpl-dahua-vuln.nse",
    "rtsp-creds":       "embedxpl-rtsp-creds.nse",
    # IoT / perimeter / router / printer
    "iot-cve-check":    "embedxpl-iot-cve-check.nse",
    "perimeter-vuln":   "embedxpl-perimeter-vuln.nse",
    "router-vuln":      "embedxpl-router-vuln.nse",
    "printer-vuln":     "embedxpl-printer-vuln.nse",
    # Suite reference
    "suite-ref":        "embedxpl-suite-ref.nse",
}

_DESCRIPTIONS: Dict[str, str] = {
    "rtsp-discover":   "RTSP service discovery + banner grab + vendor fingerprint",
    "camera-identify": "IP camera deep fingerprinting (HTTP + RTSP + ONVIF multi-protocol)",
    "camera-snapshot": "Unauthenticated camera snapshot access detector (30+ endpoints)",
    "hikvision-vuln":  "Hikvision CVE checker (CVE-2021-36260, CVE-2017-7921)",
    "dahua-vuln":      "Dahua CVE checker (CVE-2021-33044, CVE-2020-25078, CVE-2013-6117)",
    "rtsp-creds":      "Quick RTSP default credential tester (Basic auth)",
    "iot-cve-check":   "Multi-vendor IoT CVE fingerprint & validation (15+ CVEs incl. 2026)",
    "perimeter-vuln":  "Firewall/VPN CVE checker -- 15 vendors, 19+ CVEs (Fortinet/Cisco/PAN-OS/SonicWall...)",
    "router-vuln":     "SOHO router CVE checker -- 15 vendors, 14+ CVEs (TP-Link/Netgear/ASUS/MikroTik...)",
    "printer-vuln":    "Network printer CVE checker -- 11 vendors, PJL/IPP/HTTP probes (HP/Canon/Lexmark...)",
    "suite-ref":       "XPL-Forge full suite reference + GTFOBins embedded Linux quick guide",
}

_PORTS_DEFAULT = "80,443,554,5554,8080,8443,8554,9100,37777,631"


# ---------------------------------------------------------------------------
# Nmap detection -- multi-method
# ---------------------------------------------------------------------------

def _find_nmap_binary() -> Optional[str]:
    """Locate the nmap binary using multiple detection strategies.

    Returns the absolute path string or None if nmap is not installed.
    """
    # 1. shutil.which (PATH-based, fastest)
    nmap = shutil.which("nmap")
    if nmap:
        return nmap

    # 2. Windows: where.exe + registry hint
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["where", "nmap"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                first_line = result.stdout.strip().splitlines()[0]
                if first_line:
                    return first_line
        except Exception:
            pass
        # Common Windows install paths
        for candidate in (
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Nmap\nmap.exe",
        ):
            if Path(candidate).is_file():
                return candidate

    # 3. Linux / macOS: common binary paths
    for candidate in (
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
        "/opt/local/bin/nmap",
        "/snap/bin/nmap",
    ):
        if Path(candidate).is_file():
            return candidate

    return None


def _find_nmap_scripts_dir(nmap_bin: Optional[str] = None) -> Optional[Path]:
    """Locate Nmap's scripts directory using multiple strategies.

    Strategy order:
      1. Query nmap binary with --script-help (parses script dir from output)
      2. Check Nmap binary's parent directory for a 'scripts' sibling
      3. OS package manager (dpkg, rpm, brew)
      4. File-system search (locate, find)
      5. Well-known platform-specific paths

    Returns the Path to the scripts directory or None.
    """
    candidates: List[Path] = []

    # 1. Ask nmap about a known built-in script -- reveals the scripts dir
    if nmap_bin:
        try:
            result = subprocess.run(
                [nmap_bin, "--script-help", "http-title"],
                capture_output=True, text=True, timeout=10
            )
            # Output contains the full path of the script file
            for line in (result.stdout + result.stderr).splitlines():
                if "http-title.nse" in line:
                    p = Path(line.strip().split()[0])
                    if p.parent.is_dir():
                        candidates.append(p.parent)
                        break
        except Exception:
            pass

        # 2. Check nmap binary's parent for scripts sibling
        nmap_path = Path(nmap_bin).resolve()
        for scripts_relative in (
            nmap_path.parent.parent / "share" / "nmap" / "scripts",
            nmap_path.parent / "scripts",
        ):
            if scripts_relative.is_dir():
                candidates.append(scripts_relative)

    # 3. OS package manager queries
    system = platform.system()
    if system in ("Linux",):
        # Debian/Ubuntu
        try:
            result = subprocess.run(
                ["dpkg", "-L", "nmap"],
                capture_output=True, text=True, timeout=8
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.endswith("/scripts") and Path(line).is_dir():
                    candidates.append(Path(line))
        except Exception:
            pass
        # RPM (Red Hat / Fedora / CentOS)
        try:
            result = subprocess.run(
                ["rpm", "-ql", "nmap"],
                capture_output=True, text=True, timeout=8
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.endswith("/scripts") and Path(line).is_dir():
                    candidates.append(Path(line))
        except Exception:
            pass

    if system == "Darwin":
        # Homebrew
        try:
            result = subprocess.run(
                ["brew", "--prefix", "nmap"],
                capture_output=True, text=True, timeout=8
            )
            prefix = result.stdout.strip()
            if prefix:
                p = Path(prefix) / "share" / "nmap" / "scripts"
                if p.is_dir():
                    candidates.append(p)
        except Exception:
            pass

    # 4. Filesystem search (locate)
    if system in ("Linux", "Darwin"):
        try:
            result = subprocess.run(
                ["locate", "-n", "10", "http-title.nse"],
                capture_output=True, text=True, timeout=8
            )
            for line in result.stdout.splitlines():
                p = Path(line.strip())
                if p.is_file() and "http-title.nse" in p.name:
                    candidates.append(p.parent)
        except Exception:
            pass

    # 5. Well-known platform paths (fallback)
    if system in ("Linux", "Darwin"):
        for path_str in (
            "/usr/share/nmap/scripts",
            "/usr/local/share/nmap/scripts",
            "/opt/homebrew/share/nmap/scripts",
            "/opt/local/share/nmap/scripts",
        ):
            candidates.append(Path(path_str))

    elif system == "Windows":
        candidates.extend([
            Path(r"C:\Program Files (x86)\Nmap\scripts"),
            Path(r"C:\Program Files\Nmap\scripts"),
            Path(r"C:\Nmap\scripts"),
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files") + r"\Nmap\scripts"),
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)") + r"\Nmap\scripts"),
        ])

    # Return first candidate that exists and is a directory
    seen: set = set()
    for candidate in candidates:
        resolved = str(candidate.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        if candidate.is_dir():
            return candidate

    return None


def _run_updatedb(nmap_bin: str) -> bool:
    """Run ``nmap --script-updatedb`` to register newly installed scripts."""
    try:
        result = subprocess.run(
            [nmap_bin, "--script-updatedb"],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# NSEManager
# ---------------------------------------------------------------------------

class NSEManager:
    """Manages EmbedXPL NSE scripts: validate, install, uninstall, list, run.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 2.0.0
    """

    def __init__(self, scripts_dir: Optional[Path] = None) -> None:
        self._nmap_bin: Optional[str] = _find_nmap_binary()
        self._scripts_dir: Optional[Path] = scripts_dir or (
            _find_nmap_scripts_dir(self._nmap_bin) if self._nmap_bin else None
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def validate_nmap(self) -> bool:
        """Check that Nmap is installed and print a clear diagnostic.

        Returns True if Nmap is available, False otherwise.
        """
        if self._nmap_bin and Path(self._nmap_bin).is_file():
            try:
                result = subprocess.run(
                    [self._nmap_bin, "--version"],
                    capture_output=True, text=True, timeout=8
                )
                version_line = result.stdout.splitlines()[0] if result.stdout else "(unknown version)"
                print("[OK] Nmap found: {} ({})".format(self._nmap_bin, version_line.strip()))
            except Exception:
                print("[OK] Nmap binary found: {}".format(self._nmap_bin))
            if self._scripts_dir:
                print("[OK] Nmap scripts directory: {}".format(self._scripts_dir))
            else:
                print("[WARN] Nmap scripts directory not found (will try at install time).")
            return True

        # Nmap not found -- print helpful diagnostic
        print("")
        print("=" * 68)
        print("  Nmap is NOT installed or not found in PATH.")
        print("=" * 68)
        print("")
        print("Install Nmap to use the NSE scripts with automatic detection:")
        print("")
        system = platform.system()
        if system == "Linux":
            print("  Debian / Ubuntu:   sudo apt-get install nmap")
            print("  Fedora / RHEL:     sudo dnf install nmap")
            print("  Arch:              sudo pacman -S nmap")
        elif system == "Darwin":
            print("  Homebrew:          brew install nmap")
            print("  MacPorts:          sudo port install nmap")
        elif system == "Windows":
            print("  Download:          https://nmap.org/download.html")
            print("  winget:            winget install insecure.nmap")
            print("  Chocolatey:        choco install nmap")
        print("")
        print("Once installed, run:  embedxpl-nse install")
        print("")
        print("-" * 68)
        print("  NSE script files are available at:")
        self._print_local_nse_paths()
        print("")
        print("  Manual usage (without install):")
        print("  nmap --script <path/to/script.nse> -p 80,443 <target>")
        print("")
        print("  Example:")
        nse_dir = _NSE_PACKAGE_DIR
        if nse_dir.is_dir():
            example = nse_dir / "embedxpl-iot-cve-check.nse"
            print("  nmap --script {} -p 80,443 192.168.1.0/24".format(example))
        print("=" * 68)
        print("")
        return False

    def install(self, force: bool = False) -> int:
        """Copy all EmbedXPL NSE scripts to Nmap's scripts directory.

        Validates Nmap first. If Nmap is not installed, prints the local
        file paths and exits cleanly (non-error, code 0).

        Returns exit code (0 = success, 1 = error).
        """
        print("")
        print("EmbedXPL-Forge NSE Script Installer v2.0.0")
        print("-" * 50)

        # Step 1: validate nmap
        print("[1/4] Checking Nmap installation...")
        if not self.validate_nmap():
            # Not an error -- user can still use scripts manually
            return 0

        # Step 2: locate scripts directory
        print("[2/4] Locating Nmap scripts directory...")
        if not self._scripts_dir:
            self._scripts_dir = _find_nmap_scripts_dir(self._nmap_bin)

        if not self._scripts_dir:
            print("[ERR] Could not locate Nmap scripts directory.")
            print("      Specify it manually:  embedxpl-nse install --nse-dir /path/to/nmap/scripts")
            print("")
            print("      NSE files are at:")
            self._print_local_nse_paths()
            return 1

        print("      Target: {}".format(self._scripts_dir))

        # Step 3: check source exists
        print("[3/4] Verifying source NSE files...")
        if not _NSE_PACKAGE_DIR.is_dir():
            print("[ERR] NSE source directory not found: {}".format(_NSE_PACKAGE_DIR))
            print("      Install from source:  git clone + pip install -e .")
            return 1

        missing_src = []
        for name, fname in _SCRIPTS.items():
            src = _NSE_PACKAGE_DIR / fname
            if not src.exists():
                missing_src.append(fname)
        if missing_src:
            print("[WARN] Source files not found (will be skipped): {}".format(
                ", ".join(missing_src)))

        # Step 4: copy scripts
        print("[4/4] Installing scripts...")
        installed: List[str] = []
        skipped: List[str] = []
        failed: List[str] = []

        for name, fname in _SCRIPTS.items():
            src = _NSE_PACKAGE_DIR / fname
            if not src.exists():
                continue
            dst = self._scripts_dir / fname
            if dst.exists() and not force:
                skipped.append(fname)
                continue
            try:
                shutil.copy2(src, dst)
                installed.append(fname)
                print("      [OK]  {} -> {}".format(fname, dst))
            except PermissionError:
                failed.append(fname)
                print("      [ERR] Permission denied: {}".format(dst))

        print("")
        print("Results:")
        print("  Installed  : {}".format(len(installed)))
        if skipped:
            print("  Skipped    : {} (already present; use --force to overwrite)".format(len(skipped)))
        if failed:
            print("  Failed     : {} -- run with sudo/Administrator".format(len(failed)))
            print("               sudo embedxpl-nse install")

        if not installed and not failed:
            print("  All scripts already installed. Use --force to reinstall.")

        # Update nmap script database
        if installed and self._nmap_bin:
            print("")
            print("Updating nmap script database...")
            if _run_updatedb(self._nmap_bin):
                print("  [OK] nmap --script-updatedb complete")
            else:
                print("  [WARN] Could not auto-update. Run manually:")
                print("         sudo nmap --script-updatedb")

        print("")
        print("Installation complete.")
        self._print_usage_hint()
        return 1 if failed else 0

    def uninstall(self) -> None:
        """Remove all EmbedXPL NSE scripts from Nmap's scripts directory."""
        if not self._nmap_bin:
            print("[WARN] Nmap not found. Nothing to uninstall.")
            return
        if not self._scripts_dir:
            print("[WARN] Nmap scripts directory not found. Nothing to uninstall.")
            return
        removed = 0
        for _, fname in _SCRIPTS.items():
            dst = self._scripts_dir / fname
            if dst.exists():
                try:
                    dst.unlink()
                    print("  [OK] Removed: {}".format(dst))
                    removed += 1
                except PermissionError:
                    print("  [ERR] Permission denied: {}. Try with sudo.".format(dst))
        print("\nRemoved {} script(s).".format(removed))
        if self._nmap_bin:
            _run_updatedb(self._nmap_bin)

    def list(self) -> None:
        """List all EmbedXPL NSE scripts and their installation status."""
        nmap_ok = bool(self._nmap_bin)
        scripts_ok = bool(self._scripts_dir)

        print("")
        print("EmbedXPL-Forge NSE Scripts  (v2.0.0 -- {} scripts)".format(len(_SCRIPTS)))
        print("-" * 82)
        if nmap_ok:
            print("Nmap binary    : {}".format(self._nmap_bin))
        else:
            print("Nmap binary    : NOT FOUND")
        if scripts_ok:
            print("Scripts dir    : {}".format(self._scripts_dir))
        else:
            print("Scripts dir    : NOT FOUND")
        print("Local NSE dir  : {}".format(_NSE_PACKAGE_DIR))
        print("-" * 82)
        print("{:<28} {:<14} {}".format("NSE Script", "Status", "Description"))
        print("-" * 82)

        for name, fname in _SCRIPTS.items():
            full_name = "embedxpl-" + name
            if scripts_ok:
                installed = (self._scripts_dir / fname).exists()
                status = "INSTALLED" if installed else "not installed"
            else:
                status = "nmap not found"
            desc = _DESCRIPTIONS.get(name, "")
            print("  {:<26} {:<14} {}".format(full_name, status, desc))

        print("")
        if not nmap_ok:
            print("Install Nmap to use these scripts with automatic integration.")
            print("After installing Nmap, run:  embedxpl-nse install")
            print("")
            print("Manual usage (copy from):")
            self._print_local_nse_paths()
        else:
            self._print_usage_hint()

    def run(self, target: str, scripts: List[str], extra_args: Optional[str] = None,
            ports: str = _PORTS_DEFAULT, output_file: Optional[str] = None) -> int:
        """Run Nmap with selected EmbedXPL NSE scripts against a target."""
        if not self._nmap_bin:
            print("[ERROR] Nmap not found. Install Nmap to use this command.")
            return 1

        # Resolve script names
        if "all" in scripts:
            script_names = ["embedxpl-" + n for n in _SCRIPTS]
        else:
            script_names = []
            for s in scripts:
                name = s.replace("embedxpl-", "")
                if name in _SCRIPTS:
                    script_names.append("embedxpl-" + name)
                else:
                    print("[WARN] Unknown script: {}".format(s))

        if not script_names:
            print("[ERROR] No valid scripts specified.")
            return 1

        cmd = [self._nmap_bin, "-sV", "-p", ports, "--script", ",".join(script_names)]
        if extra_args:
            cmd.extend(extra_args.split())
        if output_file:
            cmd.extend(["-oN", output_file])
        cmd.append(target)

        print("[NSE] Running: {}\n".format(" ".join(cmd)))
        result = subprocess.run(cmd)
        return result.returncode

    def info(self, script_name: str) -> None:
        """Show information about a specific NSE script."""
        name = script_name.replace("embedxpl-", "")
        if name not in _SCRIPTS:
            print("Unknown script: {}".format(script_name))
            print("Available: {}".format(", ".join("embedxpl-" + k for k in _SCRIPTS)))
            return

        fname = _SCRIPTS[name]
        src = _NSE_PACKAGE_DIR / fname

        print("\nScript      : embedxpl-{}".format(name))
        print("File        : {}".format(fname))
        print("Description : {}".format(_DESCRIPTIONS.get(name, "")))
        print("Source      : {}".format(src))

        if self._scripts_dir:
            dst = self._scripts_dir / fname
            print("Installed   : {}".format("YES -- {}".format(dst) if dst.exists() else "NO"))

        if src.exists():
            print("\n--- Script header (first 30 comment lines) ---")
            with open(src, encoding="utf-8") as f:
                for line in f:
                    if not line.startswith("--"):
                        break
                    print("  " + line, end="")
        print()

    # ── CLI ────────────────────────────────────────────────────────────────

    def cli(self, args: List[str]) -> None:
        """Parse and dispatch CLI subcommands."""
        parser = argparse.ArgumentParser(
            prog="embedxpl-nse",
            description=(
                "EmbedXPL-Forge NSE Script Manager -- "
                "install, list, run and manage custom Nmap scripts"
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "Examples:\n"
                "  embedxpl-nse install\n"
                "  embedxpl-nse install --force\n"
                "  embedxpl-nse list\n"
                "  embedxpl-nse run --target 192.168.1.0/24 --scripts all\n"
                "  embedxpl-nse run --target 10.0.0.1 --scripts perimeter-vuln,router-vuln\n"
                "  embedxpl-nse uninstall\n"
                "  embedxpl-nse info hikvision-vuln\n"
            ),
        )
        sub = parser.add_subparsers(dest="command")

        # install
        p_install = sub.add_parser("install", help="Install NSE scripts to Nmap scripts directory")
        p_install.add_argument("--force", "-f", action="store_true",
                               help="Overwrite already-installed scripts")
        p_install.add_argument("--nse-dir", metavar="DIR",
                               help="Override Nmap scripts directory path")

        # uninstall
        sub.add_parser("uninstall", help="Remove EmbedXPL NSE scripts from Nmap")

        # list
        sub.add_parser("list", help="List all EmbedXPL NSE scripts and their installation status")

        # run
        p_run = sub.add_parser("run", help="Run NSE scripts against a target via Nmap")
        p_run.add_argument("--target", "-t", required=True, metavar="TARGET",
                           help="IP, CIDR, range, or hostname")
        p_run.add_argument("--scripts", "-s", default="all", metavar="SCRIPTS",
                           help="Scripts to run: 'all' or comma-separated short names "
                                "(e.g. hikvision-vuln,perimeter-vuln). Default: all")
        p_run.add_argument("--ports", "-p", default=_PORTS_DEFAULT, metavar="PORTS",
                           help="Comma-separated ports. Default: {}".format(_PORTS_DEFAULT))
        p_run.add_argument("--output", "-o", metavar="FILE",
                           help="Write nmap output to file (-oN)")
        p_run.add_argument("--args", metavar="ARGS",
                           help="Extra raw nmap arguments (quoted string)")

        # info
        p_info = sub.add_parser("info", help="Show header and status for a specific script")
        p_info.add_argument("script", metavar="SCRIPT",
                            help="Short name, e.g. 'hikvision-vuln' or 'embedxpl-perimeter-vuln'")

        # check
        sub.add_parser("check", help="Check Nmap installation and scripts directory")

        parsed = parser.parse_args(args)

        if parsed.command == "install":
            if getattr(parsed, "nse_dir", None):
                self._scripts_dir = Path(parsed.nse_dir)
            sys.exit(self.install(force=parsed.force))

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

        elif parsed.command == "check":
            ok = self.validate_nmap()
            sys.exit(0 if ok else 1)

        else:
            parser.print_help()

    # ── Helpers ────────────────────────────────────────────────────────────

    def _print_local_nse_paths(self) -> None:
        """Print the local path of each NSE file for manual installation."""
        if not _NSE_PACKAGE_DIR.is_dir():
            print("  (NSE source directory not found: {})".format(_NSE_PACKAGE_DIR))
            return
        for _, fname in _SCRIPTS.items():
            path = _NSE_PACKAGE_DIR / fname
            if path.exists():
                print("    {}".format(path))

    def _print_usage_hint(self) -> None:
        """Print common Nmap usage examples after install."""
        print("Quick start:")
        print("  nmap -p 554,5554 --script embedxpl-rtsp-discover 192.168.1.0/24")
        print("  nmap -p 80,443   --script embedxpl-perimeter-vuln 10.0.0.0/24")
        print("  nmap -p 80,443   --script embedxpl-iot-cve-check 192.168.1.0/24")
        print("  nmap -p 80,9100  --script embedxpl-printer-vuln 10.0.0.0/24")
        print("  nmap -p 80,443   --script 'embedxpl-*' 192.168.1.100")
        print("")
        print("  embedxpl-nse run --target 192.168.1.0/24 --scripts all")
        print("  embedxpl-nse run --target 10.0.0.1 --scripts perimeter-vuln,router-vuln")
        print("")
        print("Exploit after NSE detection:")
        print("  pip install embedxpl && embedxpl")
        print("  pip install firewallxpl && fxf")
        print("")
