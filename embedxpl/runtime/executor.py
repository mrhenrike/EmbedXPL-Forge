"""EmbedXPL Runtime — Main Executor (XplRuntime).

Central orchestrator: detects module language and dispatches to the
correct language executor. Supports:
  - python  (default, 95%+ of modules)
  - c       (gcc + cross-compile)
  - cpp     (g++ + cross-compile)
  - go      (go build + cache)
  - rust    (rustc/cargo)
  - ruby    (ruby .rb, MSF-compatible)

Usage in a module::

    class CameradarRTSP(BaseExploit):
        native_language = "go"
        native_source   = "native_src/go/cameradar"
        native_arch     = ["amd64", "arm64"]

    class MeltdownExploit(BaseExploit):
        native_language = "c"
        native_source   = "native_src/c/meltdown/meltdown.c"
        native_cflags   = ["-O2"]

    class MsfEternalBlue(BaseExploit):
        native_language = "ruby"
        native_source   = "native_src/ruby/ms17_010.rb"
        msf_module      = True

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

from typing import Any, Optional

from .python_exec import PythonExecutor
from .c_exec import CExecutor
from .cpp_exec import CppExecutor
from .go_exec import GoExecutor
from .rust_exec import RustExecutor
from .ruby_exec import RubyExecutor


class XplRuntime:
    """Main runtime orchestrator for multi-language EmbedXPL modules.

    Instantiate once and reuse — executors are stateless but toolchain
    detection happens at construction time.
    """

    def __init__(self) -> None:
        self._executors: dict[str, Any] = {
            "python": PythonExecutor(),
            "c":      CExecutor(),
            "cpp":    CppExecutor(),
            "go":     GoExecutor(),
            "rust":   RustExecutor(),
            "ruby":   RubyExecutor(),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        module: Any,
        args: Optional[list[str]] = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute a module using its declared native_language.

        For Python modules (no native_language or native_language='python'),
        calls module.run(**kwargs) directly.

        For native modules (C/Go/Rust/Ruby), compiles (if needed) and
        executes the binary/script pointed to by module.native_source.
        """
        lang = getattr(module, "native_language", "python") or "python"
        lang = lang.lower().strip()

        executor = self._executors.get(lang)
        if executor is None:
            return {
                "error": f"Unknown native_language '{lang}'. Supported: {list(self._executors)}",
                "returncode": -1,
            }

        if not executor.is_available():
            return {
                "error": f"Executor for '{lang}' is not available (tool missing)",
                "returncode": -1,
                "lang": lang,
            }

        return executor.run(module, args=args, timeout=timeout, **kwargs)

    def check(
        self,
        module: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run module.check() (Python modules only for now)."""
        lang = getattr(module, "native_language", "python") or "python"
        if lang == "python":
            return self._executors["python"].check(module, **kwargs)
        # For native modules, execute with check_mode=True if supported
        return self.execute(module, check_mode=True, **kwargs)

    def available_languages(self) -> dict[str, bool]:
        """Return availability status of all language executors."""
        return {
            name: exec_.is_available()
            for name, exec_ in self._executors.items()
        }

    def report(self) -> str:
        """Human-readable status of all executors."""
        lines = ["=== XplRuntime Language Executors ==="]
        for name, exec_ in self._executors.items():
            ok = "OK" if exec_.is_available() else "MISSING"
            lines.append(f"  {name:<12} {ok}")
        return "\n".join(lines)


# Module-level singleton for convenience
_runtime: Optional[XplRuntime] = None


def get_runtime() -> XplRuntime:
    """Return the global XplRuntime singleton."""
    global _runtime
    if _runtime is None:
        _runtime = XplRuntime()
    return _runtime


def execute(module: Any, **kwargs: Any) -> dict[str, Any]:
    """Convenience function: execute a module using the global runtime."""
    return get_runtime().execute(module, **kwargs)
