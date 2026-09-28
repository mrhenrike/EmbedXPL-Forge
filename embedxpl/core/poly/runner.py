# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — Multi-Language PoC Runner.

Executes PoC scripts written in Ruby, Node.js, PHP, Bash, and Python
as sub-processes. Designed to be mixed into exploit modules alongside
:class:`~embedxpl.core.poly.compiler.CCompiler` to provide full
multi-language orchestration.

Supported runtimes:
  - Ruby   (ruby)   — Metasploit-derived scripts, standalone PoCs
  - Node   (node)   — JavaScript exploit PoCs, headless-browser attacks
  - PHP    (php)    — Web-based PoC scripts
  - Bash   (bash)   — Shell one-liners and staged payloads
  - Python (python3) — Cross-invoked Python sub-scripts

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

_RUNTIME_MAP = {
    "ruby":    ["ruby"],
    "node":    ["node", "nodejs"],
    "php":     ["php", "php8", "php7"],
    "bash":    ["bash", "sh"],
    "python":  ["python3", "python"],
    "perl":    ["perl"],
    "go_run":  ["go"],
}

_EXT_MAP = {
    "ruby":   ".rb",
    "node":   ".js",
    "php":    ".php",
    "bash":   ".sh",
    "python": ".py",
    "perl":   ".pl",
    "go_run": ".go",
}


def _find_runtime(lang: str) -> Optional[str]:
    """Find runtime binary for a given language key."""
    for cmd in _RUNTIME_MAP.get(lang, []):
        if shutil.which(cmd):
            return cmd
    return None


class PolyRunner:
    """Mixin that adds multi-language script execution to exploit modules.

    Embed script source code as a string in the exploit class, then call
    :meth:`run_script` to execute it in the appropriate runtime.

    Example::

        class Exploit(PolyRunner, HTTPClient):
            _RUBY_POC = \"\"\"
            require 'net/http'
            # ... Ruby PoC code
            \"\"\"

            def run(self):
                out = self.run_script(self._RUBY_POC, lang='ruby',
                                      args=[str(self.target)])
                print_success(out)

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    def run_script(
        self,
        source: str,
        lang: str,
        args: Optional[List[str]] = None,
        timeout: int = 60,
        env: Optional[dict] = None,
        stdin_data: Optional[bytes] = None,
    ) -> str:
        """Execute a script in the specified language runtime.

        Args:
            source: Script source code as a string.
            lang: Language key: 'ruby', 'node', 'php', 'bash', 'python', 'perl'.
            args: Command-line arguments passed to the script.
            timeout: Execution timeout in seconds.
            env: Environment variables override.
            stdin_data: Optional bytes to pipe to stdin.

        Returns:
            Combined stdout + stderr output string.
        """
        runtime = _find_runtime(lang)
        if not runtime:
            msg = (f"[PolyRunner] Runtime not found for lang={lang!r}. "
                   f"Install: {_RUNTIME_MAP.get(lang, ['?'])[0]}")
            logger.warning(msg)
            return msg

        ext = _EXT_MAP.get(lang, ".tmp")
        with tempfile.NamedTemporaryFile(
            suffix=ext, delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write(source)
            script_path = f.name

        cmd = [runtime, script_path] + (args or [])
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
            logger.debug("[PolyRunner] %s exit=%d | %s",
                         lang, result.returncode, combined[:200])
            return combined
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT: {lang} script timed out after {timeout}s]"
        except Exception as exc:
            return f"[POLYRUNNER ERROR: {exc}]"
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    def run_ruby(self, source: str, args: Optional[List[str]] = None,
                 timeout: int = 60) -> str:
        """Execute Ruby script source and return output."""
        return self.run_script(source, "ruby", args, timeout)

    def run_node(self, source: str, args: Optional[List[str]] = None,
                 timeout: int = 60) -> str:
        """Execute Node.js script source and return output."""
        return self.run_script(source, "node", args, timeout)

    def run_php(self, source: str, args: Optional[List[str]] = None,
                timeout: int = 60) -> str:
        """Execute PHP script source and return output."""
        return self.run_script(source, "php", args, timeout)

    def run_bash(self, source: str, args: Optional[List[str]] = None,
                 timeout: int = 60) -> str:
        """Execute Bash/shell script source and return output."""
        return self.run_script(source, "bash", args, timeout)

    def run_perl(self, source: str, args: Optional[List[str]] = None,
                 timeout: int = 60) -> str:
        """Execute Perl script source and return output."""
        return self.run_script(source, "perl", args, timeout)

    def run_msf_module(
        self,
        module_path: str,
        options: Optional[dict] = None,
        timeout: int = 120,
    ) -> str:
        """Execute a Metasploit module via msfconsole.

        Requires msfconsole to be installed and on PATH.

        Args:
            module_path: Metasploit module path (e.g. 'exploit/multi/handler').
            options: Dict of option key→value pairs to set.
            timeout: Execution timeout in seconds.

        Returns:
            msfconsole output string.
        """
        msf = shutil.which("msfconsole")
        if not msf:
            return "[PolyRunner] msfconsole not found. Install Metasploit Framework."

        opts = "\n".join(f"set {k} {v}" for k, v in (options or {}).items())
        rc_content = f"""
use {module_path}
{opts}
run
exit
"""
        with tempfile.NamedTemporaryFile(
            suffix=".rc", delete=False, mode="w", encoding="utf-8"
        ) as f:
            f.write(rc_content)
            rc_path = f.name

        try:
            result = subprocess.run(
                [msf, "-q", "-r", rc_path],
                capture_output=True,
                timeout=timeout,
            )
            return result.stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT: msfconsole timed out after {timeout}s]"
        except Exception as exc:
            return f"[MSF ERROR: {exc}]"
        finally:
            try:
                os.unlink(rc_path)
            except Exception:
                pass

    def run_searchsploit(self, query: str) -> str:
        """Query searchsploit for exploit IDs matching a search term.

        Args:
            query: Search term (e.g. 'D-Link NAS RCE 2024').

        Returns:
            searchsploit output string.
        """
        ss = shutil.which("searchsploit")
        if not ss:
            return "[PolyRunner] searchsploit not found. Install exploitdb package."
        try:
            result = subprocess.run(
                [ss, "--json", query],
                capture_output=True,
                timeout=30,
            )
            return result.stdout.decode("utf-8", errors="replace")
        except Exception as exc:
            return f"[SEARCHSPLOIT ERROR: {exc}]"

    def fetch_exploitdb(self, edb_id: str) -> str:
        """Fetch exploit source from ExploitDB by ID (requires searchsploit).

        Args:
            edb_id: ExploitDB entry ID (numeric string).

        Returns:
            Exploit source code string.
        """
        ss = shutil.which("searchsploit")
        if not ss:
            return "[PolyRunner] searchsploit not found."
        try:
            result = subprocess.run(
                [ss, "-x", edb_id],
                capture_output=True,
                timeout=15,
            )
            return result.stdout.decode("utf-8", errors="replace")
        except Exception as exc:
            return f"[EDB ERROR: {exc}]"

    def runtime_available(self, lang: str) -> bool:
        """Check if the runtime for a given language is available.

        Args:
            lang: Language key ('ruby', 'node', 'php', 'bash', 'python', 'perl').

        Returns:
            True if runtime is on PATH, False otherwise.
        """
        return _find_runtime(lang) is not None

    def available_runtimes(self) -> dict:
        """Return dict of all language keys → available runtime paths."""
        result = {}
        for lang in _RUNTIME_MAP:
            rt = _find_runtime(lang)
            result[lang] = rt or "(not found)"
        return result
