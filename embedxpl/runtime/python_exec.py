"""EmbedXPL Runtime — Python Executor.

Passthrough executor for native Python modules (the default, 95%+ of modules).
Runs the module's run() method directly in-process.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

from typing import Any


class PythonExecutor:
    """Execute a Python exploit module in-process (default executor)."""

    name = "python"

    def run(self, module: Any, **kwargs: Any) -> dict[str, Any]:
        """Call module.run(**kwargs) directly."""
        try:
            if hasattr(module, "run"):
                result = module.run(**kwargs)
                if isinstance(result, dict):
                    return result
                return {"result": result, "returncode": 0}
            return {"error": "Module has no run() method", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}

    def check(self, module: Any, **kwargs: Any) -> dict[str, Any]:
        """Call module.check(**kwargs) directly."""
        try:
            if hasattr(module, "check"):
                result = module.check(**kwargs)
                if isinstance(result, dict):
                    return result
                return {"result": result, "returncode": 0}
            return {"error": "Module has no check() method", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}

    def is_available(self) -> bool:
        return True  # Python is always available
