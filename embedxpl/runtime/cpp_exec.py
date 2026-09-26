"""EmbedXPL Runtime — C++ Executor.

Compiles and executes C++ source files with cross-compile support.
Follows the same cache + cross-compile pattern as c_exec.py.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Optional

from .cache import get_cached_binary, store_binary
from .crosscompile import get_target

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_BUILD_TMP = _WORKSPACE_ROOT / ".tmp" / "cpp_builds"


def _ensure_tmp() -> Path:
    _BUILD_TMP.mkdir(parents=True, exist_ok=True)
    return _BUILD_TMP


class CppExecutor:
    """Compile C++ source and execute the resulting binary."""

    name = "cpp"

    def is_available(self, arch: str = "x64") -> bool:
        t = get_target(arch)
        return t.cpp_compiler is not None

    def compile(
        self,
        src_path: Path,
        arch: str = "x64",
        cxxflags: Optional[list[str]] = None,
        std: str = "c++17",
        force: bool = False,
    ) -> Optional[Path]:
        """Compile C++ src for arch. Returns binary path or None."""
        src = Path(src_path)
        if not src.exists():
            return None

        if not force:
            cached = get_cached_binary(src, arch + "_cpp")
            if cached:
                return cached

        target = get_target(arch)
        cxx = target.cpp_compiler
        if not cxx:
            return None

        _ensure_tmp()
        out_path = _BUILD_TMP / f"{src.stem}_{arch}_cpp"

        flags = list(target.cflags) + [f"-std={std}"] + (cxxflags or [])
        cmd = [cxx] + flags + [str(src), "-o", str(out_path), "-lm", "-lstdc++"]

        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if cp.returncode != 0:
                return None
            out_path.chmod(0o755)
            store_binary(src, out_path, arch + "_cpp")
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
        """Compile and run a C++ module's native_source."""
        src_path = getattr(module, "native_source", None)
        if not src_path:
            return {"error": "Module has no native_source", "returncode": -1}

        arch = getattr(module, "native_arch", "x64")
        if isinstance(arch, list):
            arch = arch[0]

        src = Path(src_path)
        if not src.is_absolute():
            src = _WORKSPACE_ROOT / "embedxpl" / src_path
        if not src.exists():
            return {"error": f"C++ source not found: {src}", "returncode": -1}

        cxxflags = getattr(module, "native_cxxflags", None)
        binary = self.compile(src, arch=arch, cxxflags=cxxflags)
        if not binary:
            return {"error": f"C++ compilation failed arch={arch}: {src}", "returncode": -1}

        try:
            cmd = [str(binary)] + (args or [])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
