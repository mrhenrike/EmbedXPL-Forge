# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — C/C++ PoC Compiler.

Provides runtime compilation of embedded C/C++ exploit source code using
any available system compiler (gcc, cc, clang, musl-gcc, mingw-w64).
Compiled binaries are cached per content-hash to avoid redundant rebuilds.

Typical usage inside an exploit module::

    from embedxpl.core.poly.compiler import CCompiler

    class Exploit(CCompiler, HTTPClient):
        _C_SOURCE = \"\"\"
        #include <stdio.h>
        #include <string.h>
        // ... exploit code
        int main(int argc, char **argv) { ... }
        \"\"\"

        def run(self):
            binary = self.compile_c(self._C_SOURCE)
            if binary:
                output = self.exec_binary(binary, [str(self.target), str(self.port)])
                print_success(output)

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Cache directory for compiled binaries
_CACHE_DIR = Path(tempfile.gettempdir()) / "embedxpl_poly_cache"
_CACHE_DIR.mkdir(exist_ok=True)


def _detect_c_compiler() -> Optional[str]:
    """Detect the best available C compiler on PATH.

    Returns:
        Compiler command string, or None if none found.
    """
    candidates = ["gcc", "cc", "clang", "musl-gcc", "i686-linux-gnu-gcc",
                  "x86_64-linux-gnu-gcc", "arm-linux-gnueabi-gcc",
                  "mipsel-linux-gnu-gcc", "mips-linux-gnu-gcc"]
    # On Windows, prioritise mingw
    if platform.system() == "Windows":
        candidates = ["gcc", "x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc",
                      "clang"] + candidates
    for cmd in candidates:
        if shutil.which(cmd):
            return cmd
    return None


def _detect_cpp_compiler() -> Optional[str]:
    """Detect the best available C++ compiler."""
    candidates = ["g++", "c++", "clang++", "x86_64-w64-mingw32-g++"]
    for cmd in candidates:
        if shutil.which(cmd):
            return cmd
    return None


def _source_hash(source: str) -> str:
    """Compute a deterministic hash of C/C++ source for caching."""
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:16]


class CCompiler:
    """Mixin that adds C/C++ compile-and-run capabilities to exploit modules.

    Embed raw C or C++ source code as a class attribute and call
    :meth:`compile_c` / :meth:`compile_cpp` to get a compiled binary path,
    then :meth:`exec_binary` to execute it and capture output.

    The compiled binary is cached in ``/tmp/embedxpl_poly_cache/`` so
    repeated ``run()`` invocations skip recompilation.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    # ── Public API ────────────────────────────────────────────────────────────

    def compile_c(
        self,
        source: str,
        extra_flags: Optional[List[str]] = None,
        target_arch: Optional[str] = None,
        static: bool = False,
        output_name: Optional[str] = None,
    ) -> Optional[Path]:
        """Compile C source code and return path to binary.

        Args:
            source: Raw C source code string.
            extra_flags: Additional compiler flags (e.g. ``["-lpthread"]``).
            target_arch: Cross-compile target (e.g. ``"mipsel-linux-gnu"``).
            static: If True, pass ``-static`` flag.
            output_name: Custom binary filename (default: auto from hash).

        Returns:
            :class:`Path` to compiled binary, or None if compilation fails.
        """
        return self._compile(source, lang="c",
                             extra_flags=extra_flags or [],
                             target_arch=target_arch,
                             static=static,
                             output_name=output_name)

    def compile_cpp(
        self,
        source: str,
        extra_flags: Optional[List[str]] = None,
        target_arch: Optional[str] = None,
        static: bool = False,
        output_name: Optional[str] = None,
    ) -> Optional[Path]:
        """Compile C++ source code and return path to binary.

        Args:
            source: Raw C++ source code string.
            extra_flags: Additional compiler flags.
            target_arch: Cross-compile target architecture prefix.
            static: If True, pass ``-static`` flag.
            output_name: Custom binary filename.

        Returns:
            :class:`Path` to compiled binary, or None if compilation fails.
        """
        return self._compile(source, lang="cpp",
                             extra_flags=extra_flags or [],
                             target_arch=target_arch,
                             static=static,
                             output_name=output_name)

    def exec_binary(
        self,
        binary_path: Path,
        args: Optional[List[str]] = None,
        timeout: int = 30,
        env: Optional[dict] = None,
        stdin_data: Optional[bytes] = None,
    ) -> str:
        """Execute a compiled binary and return combined stdout+stderr.

        Args:
            binary_path: Path to the compiled binary.
            args: Command-line arguments to pass.
            timeout: Maximum execution time in seconds.
            env: Environment variables dict.
            stdin_data: Optional bytes to pipe to stdin.

        Returns:
            Combined stdout + stderr as a string.
        """
        cmd = [str(binary_path)] + (args or [])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=env,
                input=stdin_data,
            )
            out = result.stdout.decode("utf-8", errors="replace")
            err = result.stderr.decode("utf-8", errors="replace")
            combined = (out + "\n" + err).strip()
            logger.debug("[CCompiler] exit=%d | %s", result.returncode, combined[:200])
            return combined
        except subprocess.TimeoutExpired:
            logger.warning("[CCompiler] Binary timed out after %ds", timeout)
            return f"[TIMEOUT after {timeout}s]"
        except Exception as exc:
            logger.error("[CCompiler] exec error: %s", exc)
            return f"[EXEC ERROR: {exc}]"

    def compiler_available(self) -> bool:
        """Return True if any C compiler is available on PATH."""
        return _detect_c_compiler() is not None

    def compiler_info(self) -> dict:
        """Return dict with detected compiler info."""
        cc = _detect_c_compiler()
        cxx = _detect_cpp_compiler()
        return {
            "c_compiler": cc,
            "cpp_compiler": cxx,
            "platform": platform.system(),
            "machine": platform.machine(),
            "cache_dir": str(_CACHE_DIR),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _compile(
        self,
        source: str,
        lang: str,
        extra_flags: List[str],
        target_arch: Optional[str],
        static: bool,
        output_name: Optional[str],
    ) -> Optional[Path]:
        """Internal compile dispatch for C and C++.

        Args:
            source: Source code string.
            lang: 'c' or 'cpp'.
            extra_flags: Additional compiler flags.
            target_arch: Cross-compile target prefix.
            static: If True, add -static.
            output_name: Optional custom output filename.

        Returns:
            Path to binary, or None on failure.
        """
        if lang == "c":
            compiler = _detect_c_compiler()
            if target_arch:
                cross = f"{target_arch}-gcc"
                if shutil.which(cross):
                    compiler = cross
        else:
            compiler = _detect_cpp_compiler()
            if target_arch:
                cross = f"{target_arch}-g++"
                if shutil.which(cross):
                    compiler = cross

        if not compiler:
            logger.warning("[CCompiler] No %s compiler found. Install gcc.", lang.upper())
            return None

        # Cache lookup
        src_hash = _source_hash(source + lang + "".join(extra_flags))
        ext = ".exe" if platform.system() == "Windows" else ""
        binary_name = output_name or f"embedxpl_poc_{src_hash}{ext}"
        binary_path = _CACHE_DIR / binary_name

        if binary_path.exists():
            logger.debug("[CCompiler] Cache hit: %s", binary_path)
            return binary_path

        # Write source to temp file
        suffix = ".c" if lang == "c" else ".cpp"
        with tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write(source)
            src_path = f.name

        try:
            cmd = [compiler, src_path, "-o", str(binary_path)]
            cmd += ["-O2", "-Wall", "-Wno-unused-result"]
            if static:
                cmd.append("-static")
            cmd += extra_flags

            logger.debug("[CCompiler] Compiling: %s", " ".join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60,
            )
            if result.returncode != 0:
                err_msg = result.stderr.decode("utf-8", errors="replace")
                logger.error("[CCompiler] Compilation failed:\n%s", err_msg)
                return None

            # Make executable
            binary_path.chmod(0o755)
            logger.info("[CCompiler] Compiled → %s (%d bytes)",
                        binary_path, binary_path.stat().st_size)
            return binary_path

        except subprocess.TimeoutExpired:
            logger.error("[CCompiler] Compilation timed out")
            return None
        except Exception as exc:
            logger.error("[CCompiler] Unexpected error: %s", exc)
            return None
        finally:
            try:
                os.unlink(src_path)
            except Exception:
                pass
