# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Firmware Analyzer — EmbedXPL-Forge v2.0.

Wraps binwalk, unblob, Firmwalker, and EMBA to provide a unified
firmware analysis pipeline for extracted IoT/OT firmware images.

Usage:
    python -m embedxpl.tools.firmware_analyzer --file firmware.bin
    python -m embedxpl.tools.firmware_analyzer --file firmware.bin --tool binwalk
    python -m embedxpl.tools.firmware_analyzer --file firmware.bin --tool all

Version: 1.0.0
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("firmware_analyzer")

_SUPPORTED_TOOLS = ("binwalk", "unblob", "firmwalker", "emba", "all")


def _check_tool(tool: str) -> bool:
    """Check whether an external tool is available in PATH.

    Args:
        tool: Executable name to check.

    Returns:
        True if the tool is present in PATH.
    """
    try:
        subprocess.run(
            [tool, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_binwalk(firmware_path: Path, output_dir: Path) -> Tuple[int, str]:
    """Run binwalk extraction on a firmware image.

    Args:
        firmware_path: Path to the firmware binary.
        output_dir: Directory to extract files into.

    Returns:
        Tuple of (return_code, combined stdout/stderr output).
    """
    if not _check_tool("binwalk"):
        log.warning("binwalk not found. Install: pip install binwalk or apt-get install binwalk")
        return -1, "binwalk not installed"

    extract_dir = output_dir / "binwalk_extract"
    cmd = [
        "binwalk",
        "--extract",
        "--directory", str(extract_dir),
        "--quiet",
        str(firmware_path),
    ]
    log.info("Running binwalk: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        log.info("binwalk extraction complete → %s", extract_dir)
    else:
        log.warning("binwalk exited with code %d", result.returncode)
    return result.returncode, output


def run_unblob(firmware_path: Path, output_dir: Path) -> Tuple[int, str]:
    """Run unblob extraction on a firmware image.

    Args:
        firmware_path: Path to the firmware binary.
        output_dir: Directory to extract files into.

    Returns:
        Tuple of (return_code, combined stdout/stderr output).
    """
    if not _check_tool("unblob"):
        log.warning("unblob not found. Install: pip install unblob or see https://unblob.org")
        return -1, "unblob not installed"

    extract_dir = output_dir / "unblob_extract"
    cmd = [
        "unblob",
        "--extract-dir", str(extract_dir),
        str(firmware_path),
    ]
    log.info("Running unblob: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        log.info("unblob extraction complete → %s", extract_dir)
    else:
        log.warning("unblob exited with code %d", result.returncode)
    return result.returncode, output


def run_firmwalker(extracted_dir: Path, output_dir: Path) -> Tuple[int, str]:
    """Run Firmwalker analysis on an extracted filesystem.

    Args:
        extracted_dir: Path to an extracted firmware filesystem root.
        output_dir: Directory for Firmwalker output.

    Returns:
        Tuple of (return_code, combined stdout/stderr output).
    """
    firmwalker_script = _find_firmwalker()
    if firmwalker_script is None:
        log.warning(
            "firmwalker not found. Clone from: "
            "https://github.com/craigz28/firmwalker"
        )
        return -1, "firmwalker not installed"

    report_path = output_dir / "firmwalker_report.txt"
    cmd = ["bash", firmwalker_script, str(extracted_dir), str(report_path)]
    log.info("Running Firmwalker on %s...", extracted_dir)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        log.info("Firmwalker report: %s", report_path)
    else:
        log.warning("firmwalker exited with code %d", result.returncode)
    return result.returncode, output


def _find_firmwalker() -> Optional[str]:
    """Locate Firmwalker shell script in common paths or PATH.

    Returns:
        Absolute path to firmwalker.sh, or None if not found.
    """
    candidates = [
        "firmwalker",
        "firmwalker.sh",
        "/opt/firmwalker/firmwalker.sh",
        os.path.expanduser("~/tools/firmwalker/firmwalker.sh"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
        try:
            result = subprocess.run(["which", c], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
    return None


def run_emba(firmware_path: Path, output_dir: Path) -> Tuple[int, str]:
    """Run EMBA firmware analysis on a firmware image.

    Args:
        firmware_path: Path to the firmware binary.
        output_dir: Directory for EMBA output.

    Returns:
        Tuple of (return_code, combined stdout/stderr output).
    """
    emba_dir = _find_emba()
    if emba_dir is None:
        log.warning(
            "EMBA not found. Clone from: "
            "https://github.com/e-m-b-a/emba and run sudo ./installer.sh"
        )
        return -1, "EMBA not installed"

    emba_bin = os.path.join(emba_dir, "emba.sh")
    log_dir = output_dir / "emba_output"
    cmd = [
        "sudo", "bash", emba_bin,
        "-f", str(firmware_path),
        "-l", str(log_dir),
        "-s",  # silent
    ]
    log.info("Running EMBA: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        log.info("EMBA analysis complete → %s", log_dir)
    else:
        log.warning("EMBA exited with code %d", result.returncode)
    return result.returncode, output


def _find_emba() -> Optional[str]:
    """Locate EMBA installation directory.

    Returns:
        Path to EMBA directory containing emba.sh, or None.
    """
    candidates = [
        "/opt/emba",
        os.path.expanduser("~/emba"),
        os.path.expanduser("~/tools/emba"),
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "emba.sh")):
            return c
    return None


def analyze(
    firmware_path: Path,
    output_dir: Path,
    tools: List[str],
) -> Dict[str, Tuple[int, str]]:
    """Run selected analysis tools against a firmware image.

    Args:
        firmware_path: Path to firmware binary.
        output_dir: Root output directory for all tool outputs.
        tools: List of tool names to run (subset of _SUPPORTED_TOOLS).

    Returns:
        Dict mapping tool name to (return_code, output) tuple.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Tuple[int, str]] = {}

    if not firmware_path.exists():
        log.error("Firmware file not found: %s", firmware_path)
        sys.exit(1)

    log.info("Firmware: %s (%d bytes)", firmware_path, firmware_path.stat().st_size)

    if "binwalk" in tools or "all" in tools:
        results["binwalk"] = run_binwalk(firmware_path, output_dir)

    if "unblob" in tools or "all" in tools:
        results["unblob"] = run_unblob(firmware_path, output_dir)

    if "firmwalker" in tools or "all" in tools:
        # Prefer unblob extract if available, then binwalk, else firmware dir
        extracted = None
        for candidate in [
            output_dir / "unblob_extract",
            output_dir / "binwalk_extract",
        ]:
            if candidate.exists():
                extracted = candidate
                break
        if extracted:
            results["firmwalker"] = run_firmwalker(extracted, output_dir)
        else:
            log.warning("firmwalker: no extracted filesystem found; run binwalk or unblob first")

    if "emba" in tools or "all" in tools:
        results["emba"] = run_emba(firmware_path, output_dir)

    return results


def print_summary(results: Dict[str, Tuple[int, str]]) -> None:
    """Print a human-readable summary of analysis results.

    Args:
        results: Dict of tool → (return_code, output).
    """
    print("\n" + "=" * 60)
    print("  Firmware Analysis Summary")
    print("=" * 60)
    for tool, (rc, output) in results.items():
        status = "OK" if rc == 0 else ("SKIP" if rc == -1 else "ERROR({})".format(rc))
        print("  {:15s} {}".format(tool, status))
        if output and rc not in (0, -1):
            for line in output.splitlines()[:5]:
                print("    {}".format(line))
    print("=" * 60)


def main() -> None:
    """Entry point for the firmware analyzer CLI."""
    parser = argparse.ArgumentParser(
        prog="firmware_analyzer",
        description="EmbedXPL-Forge — Firmware Analyzer (binwalk/unblob/Firmwalker/EMBA)",
    )
    parser.add_argument("--file", required=True, help="Path to firmware binary to analyze")
    parser.add_argument(
        "--tool",
        choices=list(_SUPPORTED_TOOLS),
        default="all",
        help="Analysis tool to use (default: all)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output directory (default: firmware_analysis_<filename>)",
    )
    args = parser.parse_args()

    firmware_path = Path(args.file).resolve()
    output_dir = Path(
        args.output or "firmware_analysis_{}".format(firmware_path.stem)
    ).resolve()

    log.info("Starting firmware analysis pipeline...")
    results = analyze(firmware_path, output_dir, tools=[args.tool])
    print_summary(results)


if __name__ == "__main__":
    main()
