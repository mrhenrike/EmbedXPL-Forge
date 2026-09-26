"""EmbedXPL Runtime — C Executor.

Compiles and executes C source files. Supports native x64 and cross-compilation
to ARM32, ARM64, MIPS, MIPSLE targets via the cross-compilers detected by
toolchain.py.

Binary output is cached by source hash to avoid recompilation.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from . import toolchain
from .cache import get_cached_binary, store_binary
from .crosscompile import get_target

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_BUILD_TMP = _WORKSPACE_ROOT / ".tmp" / "c_builds"


def _ensure_tmp() -> Path:
    _BUILD_TMP.mkdir(parents=True, exist_ok=True)
    return _BUILD_TMP


class CExecutor:
    """Compile C source and execute the resulting binary."""

    name = "c"

    def is_available(self, arch: str = "x64") -> bool:
        t = get_target(arch)
        return t.available

    def compile(
        self,
        src_path: Path,
        arch: str = "x64",
        cflags: Optional[list[str]] = None,
        extra_libs: Optional[list[str]] = None,
        force: bool = False,
    ) -> Optional[Path]:
        """Compile src_path for the given arch. Returns binary path or None."""
        src = Path(src_path)
        if not src.exists():
            return None

        # Check binary cache first
        if not force:
            cached = get_cached_binary(src, arch)
            if cached:
                return cached

        target = get_target(arch)
        cc = target.c_compiler
        if not cc:
            return None

        _ensure_tmp()
        out_name = f"{src.stem}_{arch}"
        out_path = _BUILD_TMP / out_name

        flags = list(target.cflags) + (cflags or [])
        libs = ["-lm"] + (extra_libs or [])
        cmd = [cc] + flags + [str(src), "-o", str(out_path)] + libs

        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if cp.returncode != 0:
                return None
            out_path.chmod(0o755)
            # Store in cache
            store_binary(src, out_path, arch)
            return out_path
        except Exception:
            return None

    def run(
        self,
        module: Any,
        args: Optional[list[str]] = None,
        timeout: int = 30,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Compile and run a C module's native_source."""
        src_path = getattr(module, "native_source", None)
        if not src_path:
            return {"error": "Module has no native_source attribute", "returncode": -1}

        arch = getattr(module, "native_arch", "x64")
        if isinstance(arch, list):
            arch = arch[0]

        # Resolve path relative to EmbedXPL root if not absolute
        src = Path(src_path)
        if not src.is_absolute():
            src = _WORKSPACE_ROOT / "embedxpl" / src_path
        if not src.exists():
            return {"error": f"C source not found: {src}", "returncode": -1}

        cflags = getattr(module, "native_cflags", None)
        binary = self.compile(src, arch=arch, cflags=cflags)
        if not binary:
            return {"error": f"C compilation failed for arch={arch}: {src}", "returncode": -1}

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

    def compile_and_run_source(
        self,
        src: str | Path,
        arch: str = "x64",
        args: Optional[list[str]] = None,
        cflags: Optional[list[str]] = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Convenience: compile a .c file and run it (no module needed)."""
        src_path = Path(src)
        binary = self.compile(src_path, arch=arch, cflags=cflags)
        if not binary:
            return {"error": f"C compilation failed: {src_path}", "returncode": -1}
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
