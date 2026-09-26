"""EmbedXPL Runtime — Rust Executor.

Compiles Rust source files or Cargo projects. Supports cross-compilation
via rustup target add and cargo build --target.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from . import toolchain
from .cache import get_cached_binary, store_binary
from .crosscompile import get_target

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_BUILD_TMP = _WORKSPACE_ROOT / ".tmp" / "rust_builds"

# Rust target triple map
_RUST_TARGET_MAP = {
    "x64":    "x86_64-unknown-linux-gnu",
    "x86":    "i686-unknown-linux-gnu",
    "arm":    "arm-unknown-linux-gnueabi",
    "armhf":  "armv7-unknown-linux-gnueabihf",
    "arm64":  "aarch64-unknown-linux-gnu",
    "mips":   "mips-unknown-linux-gnu",
    "mipsle": "mipsel-unknown-linux-gnu",
}


def _ensure_tmp() -> Path:
    _BUILD_TMP.mkdir(parents=True, exist_ok=True)
    return _BUILD_TMP


class RustExecutor:
    """Compile Rust source/projects and execute the resulting binary."""

    name = "rust"

    def is_available(self) -> bool:
        return toolchain.RUSTC is not None

    def compile_file(
        self,
        src: Path,
        arch: str = "x64",
        flags: Optional[list[str]] = None,
        force: bool = False,
    ) -> Optional[Path]:
        """Compile a single .rs file with rustc. Returns binary path or None."""
        if not self.is_available():
            return None
        src = Path(src)
        if not src.exists():
            return None

        if not force:
            cached = get_cached_binary(src, f"rs_{arch}")
            if cached:
                return cached

        _ensure_tmp()
        out_path = _BUILD_TMP / f"{src.stem}_{arch}"
        target_triple = _RUST_TARGET_MAP.get(arch)

        cmd = [toolchain.RUSTC, str(src), "-o", str(out_path)]
        if target_triple and arch != "x64":
            cmd += ["--target", target_triple]
        if flags:
            cmd += flags

        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if cp.returncode != 0:
                return None
            out_path.chmod(0o755)
            store_binary(src, out_path, f"rs_{arch}")
            return out_path
        except Exception:
            return None

    def build_cargo(
        self,
        project_dir: Path,
        arch: str = "x64",
        release: bool = True,
        force: bool = False,
    ) -> Optional[Path]:
        """Build a Cargo project. Returns binary path or None."""
        if not toolchain.CARGO:
            # Fall back to rustc if cargo not available
            return None

        project_dir = Path(project_dir)
        if not (project_dir / "Cargo.toml").exists():
            return None

        if not force:
            cached = get_cached_binary(project_dir, f"cargo_{arch}")
            if cached:
                return cached

        target_triple = _RUST_TARGET_MAP.get(arch)
        env = os.environ.copy()
        env["PATH"] = f"{Path(toolchain.CARGO).parent}:{env.get('PATH', '')}"

        cmd = [toolchain.CARGO, "build"]
        if release:
            cmd.append("--release")
        if target_triple and arch != "x64":
            cmd += ["--target", target_triple]

        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                cwd=str(project_dir), env=env,
            )
            if cp.returncode != 0:
                return None

            # Find the binary
            profile = "release" if release else "debug"
            target_dir = project_dir / "target"
            if target_triple and arch != "x64":
                binary_dir = target_dir / target_triple / profile
            else:
                binary_dir = target_dir / profile

            # Find any executable
            for f in binary_dir.iterdir():
                if f.is_file() and not f.suffix and f.stat().st_mode & 0o111:
                    store_binary(project_dir, f, f"cargo_{arch}")
                    return f
            return None
        except Exception:
            return None

    def run(
        self,
        module: Any,
        args: Optional[list[str]] = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Compile and run a Rust module's native_source."""
        if not self.is_available():
            return {"error": "Rust not available", "returncode": -1}

        src_path = getattr(module, "native_source", None)
        if not src_path:
            return {"error": "Module has no native_source", "returncode": -1}

        arch_spec = getattr(module, "native_arch", "x64")
        arch = arch_spec[0] if isinstance(arch_spec, list) else arch_spec

        src = Path(src_path)
        if not src.is_absolute():
            src = _WORKSPACE_ROOT / "embedxpl" / src_path
        if not src.exists():
            return {"error": f"Rust source not found: {src}", "returncode": -1}

        # Cargo project or single file?
        if src.is_dir() and (src / "Cargo.toml").exists():
            binary = self.build_cargo(src, arch=arch)
        else:
            binary = self.compile_file(src, arch=arch)

        if not binary:
            return {"error": f"Rust compilation failed: {src}", "returncode": -1}

        try:
            cmd = [str(binary)] + (args or [])
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "binary": str(binary),
                "arch": arch,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}
