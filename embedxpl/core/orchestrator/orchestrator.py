# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Exploit Orchestrator - Runner registry and language dispatch.

Provides ExploitOrchestrator as the central coordination class for
selecting the correct runner based on source language and executing
exploits through the compile-run pipeline.

Version: 1.0.0
"""

import os
from typing import Optional

from embedxpl.core.orchestrator.artifact import (
    CompiledArtifact,
    ArtifactCache,
)
from embedxpl.core.orchestrator.compiler import (
    CrossCompiler,
    BuildProfile,
)
from embedxpl.core.orchestrator.runner import (
    ExploitRunner,
    RunResult,
)


_LANGUAGE_MAP = {
    "python": "python",
    "py": "python",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cxx": "cpp",
    "rust": "rust",
    "rs": "rust",
    "asm": "asm",
    "assembly": "asm",
}

_EXT_TO_LANG = {
    ".py": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".rs": "rust",
    ".s": "asm",
    ".S": "asm",
    ".asm": "asm",
}

_COMPILED_LANGUAGES = {"c", "cpp", "rust"}
_INTERPRETED_LANGUAGES = {"python"}
_NATIVE_LANGUAGES = {"asm"}


class RunnerRegistry:
    """Registry for language-specific exploit runners.

    Maps language identifiers to runner callables. Supports compiled
    languages (C, C++, Rust), interpreted (Python), and native (ASM).
    """

    def __init__(self):
        self._runners = {}

    def register(self, language: str, runner_callable) -> None:
        """Register a runner for a language.

        Args:
            language: Normalized language identifier.
            runner_callable: Callable that accepts (source_path, target_opts)
                and returns a RunResult or equivalent.
        """
        self._runners[language.lower()] = runner_callable

    def get(self, language: str):
        """Get the registered runner for a language.

        Args:
            language: Language identifier.

        Returns:
            Runner callable, or None if not registered.
        """
        return self._runners.get(language.lower())

    def available_languages(self) -> list:
        """List all languages with registered runners."""
        return sorted(self._runners.keys())

    def is_registered(self, language: str) -> bool:
        """Check if a runner is registered for the language."""
        return language.lower() in self._runners


class ExploitOrchestrator:
    """Central orchestration for exploit compilation and execution.

    Manages the compile-run pipeline by selecting the appropriate runner
    based on source language, dispatching to CrossCompiler for compiled
    languages, and coordinating ExploitRunner for binary execution.

    Args:
        cache: Optional ArtifactCache for build caching.
        default_timeout: Default execution timeout in seconds.
        default_arch: Default target architecture for compilation.
    """

    def __init__(self, cache: Optional[ArtifactCache] = None,
                 default_timeout: int = 30,
                 default_arch: str = "x86_64"):
        self._cache = cache or ArtifactCache()
        self._compiler = CrossCompiler(cache=self._cache)
        self._runner = ExploitRunner(default_timeout=default_timeout)
        self._registry = RunnerRegistry()
        self._default_arch = default_arch
        self._setup_default_runners()

    def _setup_default_runners(self) -> None:
        """Register built-in runners for all supported languages."""
        for lang in _COMPILED_LANGUAGES:
            self._registry.register(lang, self._run_compiled)
        self._registry.register("python", self._run_python)
        self._registry.register("asm", self._run_asm)

    @property
    def registry(self) -> RunnerRegistry:
        """Access the runner registry."""
        return self._registry

    @property
    def compiler(self) -> CrossCompiler:
        """Access the cross-compiler."""
        return self._compiler

    @property
    def runner(self) -> ExploitRunner:
        """Access the exploit runner."""
        return self._runner

    def detect_language(self, source_path: str) -> str:
        """Detect source language from file extension.

        Args:
            source_path: Path to the source file.

        Returns:
            Normalized language identifier.

        Raises:
            ValueError: If extension is unrecognized.
        """
        ext = os.path.splitext(source_path)[1].lower()
        lang = _EXT_TO_LANG.get(ext)
        if not lang:
            raise ValueError(
                "Cannot detect language for '{}'. "
                "Supported: {}".format(ext, ", ".join(sorted(_EXT_TO_LANG.keys())))
            )
        return lang

    def select_runner(self, language: str):
        """Select the appropriate runner for a language.

        Args:
            language: Language identifier (e.g., "python", "c", "rust").

        Returns:
            Runner callable.

        Raises:
            ValueError: If no runner is registered for the language.
        """
        normalized = _LANGUAGE_MAP.get(language.lower(), language.lower())
        runner = self._registry.get(normalized)
        if not runner:
            raise ValueError(
                "No runner registered for '{}'. "
                "Available: {}".format(language, self._registry.available_languages())
            )
        return runner

    def run_exploit(self, source_path: str,
                    target_opts: Optional[dict] = None) -> RunResult:
        """Execute an exploit from source through the full pipeline.

        Detects the source language, selects the appropriate runner,
        and dispatches execution. For compiled languages, this includes
        cross-compilation before running.

        Args:
            source_path: Absolute path to the exploit source file.
            target_opts: Optional dictionary of target options:
                - arch: Target architecture (default: x86_64).
                - timeout: Execution timeout in seconds.
                - args: List of command-line arguments.
                - env: Dict of environment variables.
                - static: Boolean for static linking.
                - optimization: Compiler optimization level.

        Returns:
            RunResult with execution outcome.

        Raises:
            FileNotFoundError: If source file does not exist.
            ValueError: If language is unsupported.
            RuntimeError: If compilation or execution fails.
        """
        source_path = os.path.abspath(source_path)
        if not os.path.isfile(source_path):
            raise FileNotFoundError("Source not found: {}".format(source_path))

        opts = target_opts or {}
        language = opts.get("language") or self.detect_language(source_path)
        runner_fn = self.select_runner(language)
        return runner_fn(source_path, opts)

    def _run_compiled(self, source_path: str, opts: dict) -> RunResult:
        """Compile and run a C/C++/Rust exploit."""
        arch = opts.get("arch", self._default_arch)
        language = opts.get("language") or self.detect_language(source_path)

        profile = BuildProfile(
            target_arch=arch,
            language=language,
            optimization=opts.get("optimization", "-O2"),
            static_link=opts.get("static", False),
            extra_flags=opts.get("extra_flags", []),
        )

        artifact = self._compiler.compile(source_path, profile)

        return self._runner.run(
            artifact,
            args=opts.get("args"),
            timeout=opts.get("timeout"),
            env=opts.get("env"),
        )

    def _run_python(self, source_path: str, opts: dict) -> RunResult:
        """Run a Python exploit via interpreter."""
        import subprocess
        import time

        timeout = opts.get("timeout", 30)
        args = opts.get("args", [])
        env_vars = opts.get("env")

        proc_env = os.environ.copy()
        if env_vars:
            proc_env.update(env_vars)

        cmd = ["python3", source_path] + args
        start = time.time()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                text=True,
                env=proc_env,
            )
            elapsed = time.time() - start
            return RunResult(
                exit_code=result.returncode,
                stdout=result.stdout[:1048576],
                stderr=result.stderr[:1048576],
                elapsed=elapsed,
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                exit_code=-1,
                timed_out=True,
                elapsed=time.time() - start,
            )
        except (FileNotFoundError, OSError) as exc:
            return RunResult(
                exit_code=-1,
                stderr="Python execution error: {}".format(exc),
            )

    def _run_asm(self, source_path: str, opts: dict) -> RunResult:
        """Assemble, link, and run an assembly exploit."""
        import shutil
        import subprocess
        import time

        nasm = shutil.which("nasm")
        ld = shutil.which("ld")
        if not nasm:
            return RunResult(exit_code=-1, stderr="nasm assembler not found")
        if not ld:
            return RunResult(exit_code=-1, stderr="ld linker not found")

        base = os.path.splitext(os.path.basename(source_path))[0]
        tmp_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp", "builds"
        )
        os.makedirs(tmp_dir, exist_ok=True)
        obj_path = os.path.join(tmp_dir, "{}.o".format(base))
        bin_path = os.path.join(tmp_dir, base)

        arch = opts.get("arch", self._default_arch)
        fmt = "elf64" if "64" in arch else "elf32"

        try:
            asm_result = subprocess.run(
                [nasm, "-f", fmt, source_path, "-o", obj_path],
                capture_output=True, text=True, timeout=30,
            )
            if asm_result.returncode != 0:
                return RunResult(exit_code=asm_result.returncode, stderr=asm_result.stderr)

            ld_result = subprocess.run(
                [ld, obj_path, "-o", bin_path],
                capture_output=True, text=True, timeout=30,
            )
            if ld_result.returncode != 0:
                return RunResult(exit_code=ld_result.returncode, stderr=ld_result.stderr)
        except subprocess.TimeoutExpired:
            return RunResult(exit_code=-1, timed_out=True)

        artifact = CompiledArtifact(
            source_hash="",
            binary_path=bin_path,
            target_arch=arch,
            compiler_used="nasm+ld",
            build_time=0,
            source_path=source_path,
        )
        return self._runner.run(
            artifact,
            args=opts.get("args"),
            timeout=opts.get("timeout"),
            env=opts.get("env"),
        )
