"""EmbedXPL Runtime — Ruby Executor.

Runs Ruby scripts (.rb) with optional Metasploit Framework integration.
Supports both standalone ruby scripts and MSF-format modules.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Optional

from . import toolchain

_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


class RubyExecutor:
    """Execute Ruby scripts, with optional MSF module support."""

    name = "ruby"

    def is_available(self) -> bool:
        return toolchain.RUBY is not None

    def run(
        self,
        module: Any,
        args: Optional[list[str]] = None,
        use_msf: Optional[bool] = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run a Ruby module's native_source."""
        if not self.is_available():
            return {"error": "Ruby not available", "returncode": -1}

        src_path = getattr(module, "native_source", None)
        if not src_path:
            return {"error": "Module has no native_source", "returncode": -1}

        src = Path(src_path)
        if not src.is_absolute():
            src = _WORKSPACE_ROOT / "embedxpl" / src_path
        if not src.exists():
            return {"error": f"Ruby source not found: {src}", "returncode": -1}

        # Determine runner
        is_msf_module = use_msf if use_msf is not None else getattr(module, "msf_module", False)
        if is_msf_module and toolchain.MSFCONSOLE:
            cmd = [toolchain.MSFCONSOLE, "-r", str(src)] + (args or [])
        else:
            cmd = [toolchain.RUBY, str(src)] + (args or [])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "runner": "msfconsole" if is_msf_module and toolchain.MSFCONSOLE else "ruby",
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}

    def run_script(
        self,
        src: str | Path,
        args: Optional[list[str]] = None,
        timeout: int = 60,
        env: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Run any Ruby script directly (no module needed)."""
        if not self.is_available():
            return {"error": "Ruby not available", "returncode": -1}
        try:
            import os
            run_env = os.environ.copy()
            if env:
                run_env.update(env)
            result = subprocess.run(
                [toolchain.RUBY, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout, env=run_env,
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

    def run_msf_module(
        self,
        src: str | Path,
        options: Optional[dict[str, str]] = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Execute an MSF module via msfconsole -r with options set."""
        if not toolchain.MSFCONSOLE:
            return {"error": "msfconsole not available", "returncode": -1}

        # Build MSF resource file with options
        lines = [f"use {src}"]
        for k, v in (options or {}).items():
            lines.append(f"set {k} {v}")
        lines.append("run")
        lines.append("exit")

        import tempfile, os
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False, prefix="embedxpl_msf_"
        ) as f:
            f.write("\n".join(lines))
            rc_file = f.name

        try:
            result = subprocess.run(
                [toolchain.MSFCONSOLE, "-q", "-r", rc_file],
                capture_output=True, text=True, timeout=timeout,
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
        finally:
            try:
                os.unlink(rc_file)
            except Exception:
                pass
