"""EmbedXPL Runtime — Toolchain Detection.

Auto-detects all available compilers and language runtimes at import time.
Results are cached as module-level constants so detection runs only once.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional


def _version(cmd: str) -> Optional[str]:
    """Return first line of `cmd --version`, or None if not found."""
    binary = shutil.which(cmd)
    if not binary:
        return None
    try:
        r = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        line = (r.stdout or r.stderr or "").splitlines()
        return line[0].strip() if line else "unknown"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Native compilers
# ---------------------------------------------------------------------------

GCC: Optional[str] = shutil.which("gcc")
GPP: Optional[str] = shutil.which("g++")
CLANG: Optional[str] = shutil.which("clang")
CLANGPP: Optional[str] = shutil.which("clang++")

# ---------------------------------------------------------------------------
# Cross-compilers
# ---------------------------------------------------------------------------

CROSS_COMPILERS: dict[str, Optional[str]] = {
    "arm":    shutil.which("arm-linux-gnueabi-gcc"),
    "armhf":  shutil.which("arm-linux-gnueabihf-gcc"),
    "arm64":  shutil.which("aarch64-linux-gnu-gcc"),
    "mips":   shutil.which("mips-linux-gnu-gcc"),
    "mipsle": shutil.which("mipsel-linux-gnu-gcc"),
    "mips64": shutil.which("mips64-linux-gnuabi64-gcc"),
    "x86":    GCC,
    "x64":    GCC,
    "musl":   shutil.which("musl-gcc"),
}

CROSS_CPP_COMPILERS: dict[str, Optional[str]] = {
    "arm":    shutil.which("arm-linux-gnueabi-g++"),
    "arm64":  shutil.which("aarch64-linux-gnu-g++"),
    "mips":   shutil.which("mips-linux-gnu-g++"),
    "mipsle": shutil.which("mipsel-linux-gnu-g++"),
    "x86":    GPP,
    "x64":    GPP,
}

# ---------------------------------------------------------------------------
# Language runtimes
# ---------------------------------------------------------------------------

GO: Optional[str] = shutil.which("go")
RUSTC: Optional[str] = shutil.which("rustc")
CARGO: Optional[str] = shutil.which("cargo")
RUBY: Optional[str] = shutil.which("ruby")
PYTHON: Optional[str] = shutil.which("python3") or shutil.which("python")
MSFCONSOLE: Optional[str] = shutil.which("msfconsole")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def available() -> dict[str, bool]:
    """Return dict of tool availability."""
    return {
        "gcc":     GCC is not None,
        "g++":     GPP is not None,
        "clang":   CLANG is not None,
        "clang++": CLANGPP is not None,
        "go":      GO is not None,
        "rustc":   RUSTC is not None,
        "cargo":   CARGO is not None,
        "ruby":    RUBY is not None,
        "python3": PYTHON is not None,
        "msf":     MSFCONSOLE is not None,
        # Cross-compilers
        **{f"cross_{k}": v is not None for k, v in CROSS_COMPILERS.items()},
    }


def get_c_compiler(arch: str = "x64") -> Optional[str]:
    """Return the best C compiler for the requested architecture."""
    cc = CROSS_COMPILERS.get(arch)
    return cc or GCC or CLANG


def get_cpp_compiler(arch: str = "x64") -> Optional[str]:
    """Return the best C++ compiler for the requested architecture."""
    cc = CROSS_CPP_COMPILERS.get(arch)
    return cc or GPP or CLANGPP


def report() -> str:
    """Human-readable toolchain status report."""
    lines = ["=== EmbedXPL Toolchain ==="]
    avail = available()
    for tool, ok in sorted(avail.items()):
        status = "OK" if ok else "MISSING"
        lines.append(f"  {tool:<28} {status}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
