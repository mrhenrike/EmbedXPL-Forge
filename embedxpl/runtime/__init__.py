"""EmbedXPL Multi-Language Runtime.

Provides language executors for Python, C, C++, Go, Rust, and Ruby modules.
Enables cross-compilation to ARM32, ARM64, MIPS, MIPSLE targets.

Quick start::

    from embedxpl.runtime import XplRuntime

    runtime = XplRuntime()
    print(runtime.report())          # check all executors
    result = runtime.execute(module) # run any module

Or using the module-level singleton::

    from embedxpl.runtime import execute
    result = execute(my_module)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from .cache import cache_info, clear_cache
from .crosscompile import TARGETS, available_targets, get_target
from .executor import XplRuntime, execute, get_runtime
from .toolchain import available as toolchain_available
from .toolchain import report as toolchain_report

__all__ = [
    "TARGETS",
    "XplRuntime",
    "available_targets",
    "cache_info",
    "clear_cache",
    "execute",
    "get_runtime",
    "get_target",
    "toolchain_available",
    "toolchain_report",
]
