# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Cross-Compiler - Toolchain detection and multi-architecture compilation.

Provides CrossCompiler and BuildProfile for compiling C, C++, and Rust
source files to target architectures (x86, x86_64, ARM, MIPS, RISC-V)
using detected system toolchains.

Version: 1.0.0
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from embedxpl.core.orchestrator.artifact import (
    CompiledArtifact,
    ArtifactCache,
)


_PROJECT_TMP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp"
)

_TOOLCHAIN_MAP = {
    "x86": {
        "c": "gcc",
        "cpp": "g++",
        "rust": "rustc",
    },
    "x86_64": {
        "c": "gcc",
        "cpp": "g++",
        "rust": "rustc",
    },
    "arm": {
        "c": "arm-none-eabi-gcc",
        "cpp": "arm-none-eabi-g++",
        "rust": "rustc",
    },
    "mips": {
        "c": "mips-linux-gnu-gcc",
        "cpp": "mips-linux-gnu-g++",
        "rust": "rustc",
    },
    "riscv": {
        "c": "riscv64-unknown-elf-gcc",
        "cpp": "riscv64-unknown-elf-g++",
        "rust": "rustc",
    },
}

_RUST_TARGETS = {
    "x86": "i686-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
    "arm": "armv7-unknown-linux-gnueabihf",
    "mips": "mips-unknown-linux-gnu",
    "riscv": "riscv64gc-unknown-linux-gnu",
}

_LANG_EXTENSIONS = {
    ".c": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".rs": "rust",
}


@dataclass
class BuildProfile:
    """Compilation profile for a target build.

    Attributes:
        target_arch: Target architecture (x86, x86_64, arm, mips, riscv).
        language: Source language (c, cpp, rust).
        optimization: Optimization level (-O0, -O1, -O2, -Os, -O3).
        static_link: Link statically if True.
        strip_symbols: Strip debug symbols from output.
        extra_flags: Additional compiler flags.
    """

    target_arch: str = "x86_64"
    language: str = "c"
    optimization: str = "-O2"
    static_link: bool = False
    strip_symbols: bool = True
    extra_flags: list = field(default_factory=list)

    def validate(self) -> None:
        """Validate profile parameters.

        Raises:
            ValueError: If target_arch or language is unsupported.
        """
        valid_archs = set(_TOOLCHAIN_MAP.keys())
        if self.target_arch not in valid_archs:
            raise ValueError(
                "Unsupported architecture '{}'. Valid: {}".format(
                    self.target_arch, ", ".join(sorted(valid_archs))
                )
            )
        valid_langs = {"c", "cpp", "rust"}
        if self.language not in valid_langs:
            raise ValueError(
                "Unsupported language '{}'. Valid: {}".format(
                    self.language, ", ".join(sorted(valid_langs))
                )
            )


class CrossCompiler:
    """Cross-compilation engine with toolchain detection and caching.

    Detects installed toolchains (gcc, arm-none-eabi-gcc,
    mips-linux-gnu-gcc, rustc), compiles C/C++/Rust source to target
    architectures, and returns CompiledArtifact results.

    Args:
        cache: Optional ArtifactCache instance. Created automatically
            if not provided.
    """

    def __init__(self, cache: Optional[ArtifactCache] = None):
        self._cache = cache or ArtifactCache()
        self._detected = {}

    def detect_toolchains(self) -> dict:
        """Detect available compiler toolchains on the system.

        Returns:
            Dictionary mapping compiler names to their absolute paths.
        """
        compilers = set()
        for arch_map in _TOOLCHAIN_MAP.values():
            for compiler in arch_map.values():
                compilers.add(compiler)

        self._detected = {}
        for compiler in compilers:
            path = shutil.which(compiler)
            if path:
                self._detected[compiler] = path
        return dict(self._detected)

    def is_available(self, profile: BuildProfile) -> bool:
        """Check if the required compiler is available for a build profile.

        Args:
            profile: BuildProfile specifying arch and language.

        Returns:
            True if the required compiler is installed.
        """
        if not self._detected:
            self.detect_toolchains()
        compiler = self._resolve_compiler(profile)
        return compiler in self._detected

    def _resolve_compiler(self, profile: BuildProfile) -> str:
        """Resolve the compiler binary name for a build profile."""
        arch_map = _TOOLCHAIN_MAP.get(profile.target_arch, {})
        return arch_map.get(profile.language, "")

    def _detect_language(self, source_path: str) -> str:
        """Detect source language from file extension.

        Args:
            source_path: Path to the source file.

        Returns:
            Language string (c, cpp, rust).

        Raises:
            ValueError: If extension is unrecognized.
        """
        ext = os.path.splitext(source_path)[1].lower()
        lang = _LANG_EXTENSIONS.get(ext)
        if not lang:
            raise ValueError(
                "Unrecognized source extension '{}'. "
                "Supported: {}".format(ext, ", ".join(_LANG_EXTENSIONS.keys()))
            )
        return lang

    def _build_gcc_command(self, source_path: str, output_path: str,
                           compiler: str, profile: BuildProfile) -> list:
        """Build gcc/g++ compilation command."""
        cmd = [compiler, source_path, "-o", output_path, profile.optimization]
        if profile.static_link:
            cmd.append("-static")
        if profile.strip_symbols:
            cmd.append("-s")
        cmd.extend(profile.extra_flags)
        return cmd

    def _build_rustc_command(self, source_path: str, output_path: str,
                             profile: BuildProfile) -> list:
        """Build rustc compilation command."""
        target = _RUST_TARGETS.get(profile.target_arch, "")
        cmd = ["rustc", source_path, "-o", output_path]
        if target:
            cmd.extend(["--target", target])
        opt_map = {"-O0": "0", "-O1": "1", "-O2": "2", "-O3": "3", "-Os": "s"}
        opt_level = opt_map.get(profile.optimization, "2")
        cmd.extend(["-C", "opt-level={}".format(opt_level)])
        if profile.strip_symbols:
            cmd.extend(["-C", "debuginfo=0"])
        cmd.extend(profile.extra_flags)
        return cmd

    def compile(self, source_path: str,
                profile: Optional[BuildProfile] = None) -> CompiledArtifact:
        """Compile source file to target architecture.

        Checks the artifact cache first. On cache miss, runs the
        compiler and stores the result.

        Args:
            source_path: Absolute path to the source file.
            profile: BuildProfile with compilation settings. If None,
                defaults to x86_64 with auto-detected language.

        Returns:
            CompiledArtifact with build result.

        Raises:
            FileNotFoundError: If source_path does not exist.
            ValueError: If language or architecture is unsupported.
            RuntimeError: If compilation fails.
        """
        source_path = os.path.abspath(source_path)
        if not os.path.isfile(source_path):
            raise FileNotFoundError("Source file not found: {}".format(source_path))

        if profile is None:
            lang = self._detect_language(source_path)
            profile = BuildProfile(language=lang)
        profile.validate()

        if not self._detected:
            self.detect_toolchains()

        compiler = self._resolve_compiler(profile)
        if not compiler or compiler not in self._detected:
            raise RuntimeError(
                "Compiler '{}' not found for {}/{}".format(
                    compiler, profile.target_arch, profile.language
                )
            )

        cached = self._cache.lookup(source_path, profile.target_arch, compiler)
        if cached:
            return cached

        output_dir = os.path.join(_PROJECT_TMP, "builds", "staging")
        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(source_path))[0]
        output_path = os.path.join(output_dir, "{}_{}".format(base_name, profile.target_arch))

        if profile.language in ("c", "cpp"):
            cmd = self._build_gcc_command(
                source_path, output_path, self._detected[compiler], profile
            )
        else:
            cmd = self._build_rustc_command(source_path, output_path, profile)

        build_start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
                text=True,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Compilation timed out after 120 seconds")
        except FileNotFoundError:
            raise RuntimeError("Compiler binary not found: {}".format(compiler))

        build_time = time.time() - build_start

        source_hash = self._cache._compute_source_hash(source_path)
        artifact = CompiledArtifact(
            source_hash=source_hash,
            binary_path=output_path,
            target_arch=profile.target_arch,
            compiler_used=compiler,
            build_time=build_time,
            cached=False,
            source_path=source_path,
            build_flags=" ".join(cmd[1:]),
            binary_size=os.path.getsize(output_path) if os.path.isfile(output_path) else 0,
            exit_code=result.returncode,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Compilation failed (exit {}): {}".format(
                    result.returncode, result.stderr.strip()[:500]
                )
            )

        artifact = self._cache.store(artifact)
        return artifact
