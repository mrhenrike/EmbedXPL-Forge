"""EmbedXPL Runtime — Go Executor.

Builds Go source trees or single .go files and executes the resulting binary.
Supports cross-compilation via GOOS/GOARCH environment variables.
Uses binary cache to avoid recompilation.

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
_BUILD_TMP = _WORKSPACE_ROOT / ".tmp" / "go_builds"

# Go arch mappings (embedxpl arch name -> GOARCH)
_GOARCH_MAP = {
    "x64":    "amd64",
    "x86":    "386",
    "arm":    "arm",
    "armhf":  "arm",
    "arm64":  "arm64",
    "mips":   "mips",
    "mipsle": "mipsle",
    "mips64": "mips64",
}


def _ensure_tmp() -> Path:
    _BUILD_TMP.mkdir(parents=True, exist_ok=True)
    return _BUILD_TMP


class GoExecutor:
    """Build Go projects and execute resulting binaries."""

    name = "go"

    def is_available(self) -> bool:
        return toolchain.GO is not None

    def build(
        self,
        src: Path,
        arch: str = "x64",
        goos: str = "linux",
        ldflags: Optional[str] = None,
        force: bool = False,
    ) -> Optional[Path]:
        """Build Go source (file or directory). Returns binary path or None."""
        if not self.is_available():
            return None

        src = Path(src)
        if not src.exists():
            return None

        # For directory: use the directory; for file: use its parent
        build_src = str(src) if src.is_dir() else str(src.parent)
        build_key = src

        if not force:
            cached = get_cached_binary(src, f"go_{arch}_{goos}")
            if cached:
                return cached

        _ensure_tmp()
        goarch = _GOARCH_MAP.get(arch, "amd64")
        out_name = f"{src.name if src.is_dir() else src.stem}_{arch}"
        out_path = _BUILD_TMP / out_name

        env = os.environ.copy()
        env["GOOS"] = goos
        env["GOARCH"] = goarch
        env["CGO_ENABLED"] = "0"  # static build for portability

        go_binary = toolchain.GO
        cmd = [go_binary, "build", "-o", str(out_path)]
        if ldflags:
            cmd += ["-ldflags", ldflags]
        cmd.append(build_src)

        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, env=env,
                cwd=str(src if src.is_dir() else src.parent),
            )
            if cp.returncode != 0:
                return None
            out_path.chmod(0o755)
            store_binary(src, out_path, f"go_{arch}_{goos}")
            return out_path
        except subprocess.TimeoutExpired:
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
        """Build and run a Go module's native_source."""
        if not self.is_available():
            return {"error": "Go not available", "returncode": -1}

        src_path = getattr(module, "native_source", None)
        if not src_path:
            return {"error": "Module has no native_source", "returncode": -1}

        arch_spec = getattr(module, "native_arch", "x64")
        arch = arch_spec[0] if isinstance(arch_spec, list) else arch_spec
        goos = getattr(module, "native_goos", "linux")
        ldflags = getattr(module, "native_ldflags", None)

        src = Path(src_path)
        if not src.is_absolute():
            src = _WORKSPACE_ROOT / "embedxpl" / src_path
        if not src.exists():
            return {"error": f"Go source not found: {src}", "returncode": -1}

        binary = self.build(src, arch=arch, goos=goos, ldflags=ldflags)
        if not binary:
            return {"error": f"Go build failed: {src} (arch={arch})", "returncode": -1}

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
                "goos": goos,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}

    def run_source_file(
        self,
        src: str | Path,
        args: Optional[list[str]] = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Run a Go source file directly with `go run` (no caching, for dev)."""
        if not self.is_available():
            return {"error": "Go not available", "returncode": -1}
        try:
            cmd = [toolchain.GO, "run", str(src)] + (args or [])
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}
