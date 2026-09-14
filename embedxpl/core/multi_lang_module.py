"""EmbedXPL Multi-Language Module Support.

Provides mixins and utilities for modules that embed non-Python exploit code
(C, Ruby, Bash, HTML, JS) within the native_src/ directory and compile/execute
it at runtime via subprocess.

Original code
-------------
Author: Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
_NATIVE_SRC = _WORKSPACE_ROOT / "embedxpl" / "resources" / "native_src"


def _workspace_tmp() -> Path:
    """Return workspace-local .tmp/ directory (never OS /tmp)."""
    tmp = _WORKSPACE_ROOT / ".tmp" / "native_builds"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


class MultiLangModule:
    """Mixin for exploit modules that run non-Python native source code."""

    def run_c_source(
        self,
        src_path: str | Path,
        args: list[str] | None = None,
        timeout: int = 30,
        compiler: str = "gcc",
    ) -> dict[str, Any]:
        """Compile C source from native_src/ and run the binary in .tmp/."""
        src = Path(src_path)
        if not src.is_absolute():
            src = _NATIVE_SRC / src
        if not src.exists():
            return {"error": f"C source not found: {src}", "returncode": -1}

        cc = shutil.which(compiler) or shutil.which("cc")
        if not cc:
            return {"error": f"Compiler '{compiler}' not found", "returncode": -1}

        tmp = _workspace_tmp()
        binary = tmp / f"{src.stem}_compiled"

        # Compile
        compile_cmd = [cc, str(src), "-o", str(binary), "-lm"]
        try:
            cp = subprocess.run(
                compile_cmd,
                capture_output=True, text=True, timeout=60,
            )
            if cp.returncode != 0:
                return {"error": f"Compile failed: {cp.stderr[:200]}", "returncode": cp.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "Compile timeout", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}

        # Run
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
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"error": str(exc), "returncode": -1}
        finally:
            # Clean binary after use
            try:
                binary.unlink(missing_ok=True)
            except Exception:
                pass

    def run_ruby_source(
        self,
        src_path: str | Path,
        args: list[str] | None = None,
        timeout: int = 60,
        use_msfconsole: bool = False,
    ) -> dict[str, Any]:
        """Run a Ruby script from native_src/ via ruby or msfconsole."""
        src = Path(src_path)
        if not src.is_absolute():
            src = _NATIVE_SRC / src
        if not src.exists():
            return {"error": f"Ruby source not found: {src}", "returncode": -1}

        if use_msfconsole and shutil.which("msfconsole"):
            cmd = ["msfconsole", "-r", str(src)] + (args or [])
        elif shutil.which("ruby"):
            cmd = ["ruby", str(src)] + (args or [])
        else:
            return {"error": "ruby/msfconsole not found", "returncode": -1}

        try:
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

    def run_bash_source(
        self,
        src_path: str | Path,
        args: list[str] | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Run a Bash script from native_src/ in workspace .tmp/."""
        src = Path(src_path)
        if not src.is_absolute():
            src = _NATIVE_SRC / src
        if not src.exists():
            return {"error": f"Bash source not found: {src}", "returncode": -1}

        sh = shutil.which("bash") or shutil.which("sh")
        if not sh:
            return {"error": "bash/sh not found", "returncode": -1}

        try:
            result = subprocess.run(
                [sh, str(src)] + (args or []),
                capture_output=True, text=True, timeout=timeout,
                cwd=str(_workspace_tmp()),
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

    def write_and_serve_html(self, html_content: str, port: int = 8080) -> dict[str, Any]:
        """Write HTML payload to .tmp/ and start a minimal HTTP server."""
        import threading
        import http.server

        tmp = _workspace_tmp()
        html_file = tmp / "payload.html"
        html_file.write_text(html_content, encoding="utf-8")

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=str(tmp), **kw)
            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("0.0.0.0", port), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return {
            "url": f"http://0.0.0.0:{port}/payload.html",
            "server": server,
            "file": str(html_file),
        }
