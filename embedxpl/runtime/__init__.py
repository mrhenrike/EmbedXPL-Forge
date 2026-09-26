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
from .executor import XplRuntime, get_runtime, execute
from .toolchain import available as toolchain_available, report as toolchain_report
from .crosscompile import available_targets, get_target, TARGETS
from .cache import cache_info, clear_cache

__all__ = [
    "XplRuntime",
    "get_runtime",
    "execute",
    "toolchain_available",
    "toolchain_report",
    "available_targets",
    "get_target",
    "TARGETS",
    "cache_info",
    "clear_cache",
]
