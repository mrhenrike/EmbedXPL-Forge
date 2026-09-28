"""EmbedXPL Runtime — Cross-Compilation Targets.

Maps architecture names to cross-compiler binaries and build flags.
Supports: ARM32, ARM64, MIPS BE, MIPS LE, x86, x64.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from . import toolchain


@dataclass
class CrossTarget:
    """Describes a cross-compilation target."""
    arch: str
    c_compiler: Optional[str]
    cpp_compiler: Optional[str]
    cflags: list[str] = field(default_factory=list)
    ldflags: list[str] = field(default_factory=list)
    go_goarch: Optional[str] = None
    go_goos: str = "linux"
    rust_target: Optional[str] = None
    available: bool = False

    def __post_init__(self) -> None:
        self.available = self.c_compiler is not None


# ---------------------------------------------------------------------------
# Target definitions
# ---------------------------------------------------------------------------

TARGETS: dict[str, CrossTarget] = {
    "x64": CrossTarget(
        arch="x64",
        c_compiler=toolchain.GCC,
        cpp_compiler=toolchain.GPP,
        cflags=["-m64"],
        go_goarch="amd64",
        rust_target="x86_64-unknown-linux-gnu",
    ),
    "x86": CrossTarget(
        arch="x86",
        c_compiler=toolchain.GCC,
        cpp_compiler=toolchain.GPP,
        cflags=["-m32"],
        go_goarch="386",
        rust_target="i686-unknown-linux-gnu",
    ),
    "arm": CrossTarget(
        arch="arm",
        c_compiler=toolchain.CROSS_COMPILERS.get("arm"),
        cpp_compiler=toolchain.CROSS_CPP_COMPILERS.get("arm"),
        cflags=["-march=armv6", "-mfloat-abi=soft"],
        go_goarch="arm",
        rust_target="arm-unknown-linux-gnueabi",
    ),
    "armhf": CrossTarget(
        arch="armhf",
        c_compiler=toolchain.CROSS_COMPILERS.get("armhf"),
        cpp_compiler=None,
        cflags=["-march=armv7-a", "-mfpu=vfpv3-d16", "-mfloat-abi=hard"],
        go_goarch="arm",
        rust_target="armv7-unknown-linux-gnueabihf",
    ),
    "arm64": CrossTarget(
        arch="arm64",
        c_compiler=toolchain.CROSS_COMPILERS.get("arm64"),
        cpp_compiler=toolchain.CROSS_CPP_COMPILERS.get("arm64"),
        cflags=[],
        go_goarch="arm64",
        rust_target="aarch64-unknown-linux-gnu",
    ),
    "mips": CrossTarget(
        arch="mips",
        c_compiler=toolchain.CROSS_COMPILERS.get("mips"),
        cpp_compiler=toolchain.CROSS_CPP_COMPILERS.get("mips"),
        cflags=["-EB", "-march=mips32"],
        go_goarch="mips",
        rust_target="mips-unknown-linux-gnu",
    ),
    "mipsle": CrossTarget(
        arch="mipsle",
        c_compiler=toolchain.CROSS_COMPILERS.get("mipsle"),
        cpp_compiler=toolchain.CROSS_CPP_COMPILERS.get("mipsle"),
        cflags=["-EL", "-march=mips32"],
        go_goarch="mipsle",
        rust_target="mipsel-unknown-linux-gnu",
    ),
    # musl-based (static, no glibc dependency)
    "musl-x64": CrossTarget(
        arch="musl-x64",
        c_compiler=toolchain.CROSS_COMPILERS.get("musl"),
        cpp_compiler=None,
        cflags=["-static"],
        ldflags=["-static"],
        go_goarch="amd64",
    ),
}


def get_target(arch: str) -> CrossTarget:
    """Return CrossTarget for the given arch name. Falls back to x64."""
    return TARGETS.get(arch, TARGETS["x64"])


def available_targets() -> list[str]:
    """Return list of architectures that have compilers available."""
    return [name for name, t in TARGETS.items() if t.available]


def report() -> str:
    lines = ["=== Cross-Compile Targets ==="]
    for name, t in TARGETS.items():
        ok = "OK" if t.available else "MISSING"
        lines.append(f"  {name:<16} {ok}  ({t.c_compiler or 'no compiler'})")
    return "\n".join(lines)


if __name__ == "__main__":
    print(report())
